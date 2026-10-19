// Package gadget adds a standard HID function to Android's existing USB gadget.
// It never selects an Android USB mode or replaces the gadget's native functions.
package gadget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const functionName = "hid.abk_fido"
const linkName = "abk_fido"

// FIDO report descriptor: usage page 0xf1d0, 64-byte input and output reports,
// no report ID, no boot protocol, and no keyboard/mouse subclass.
var reportDescriptor = []byte{
	0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20,
	0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40,
	0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00,
	0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
}

// Manager watches HAL configuration changes and restores only its own HID link.
// Root may name the configfs mount or its usb_gadget directory. DeviceRoot
// defaults to /dev. Run must be called only once per Manager.
type Manager struct {
	Root         string
	DeviceRoot   string
	PollInterval time.Duration
	// OnError receives changed reconciliation errors and nil on recovery.
	// A disconnected host is normal, and is reported through onDevice only.
	OnError func(error)

	root, builtinPath string
	udcRoot           string
	write             func(string, []byte) error
	checkDevice       func(string) error
	readState         func(string) (string, bool, error)
	state             udcStateWatcher
	pause             func(time.Duration)
	observed, failed  string
	failedError       error
	deviceKey         string
	devicePath        string
	resetEpoch        atomic.Uint64
	seenReset         uint64
}

// Reset requests a fresh USB session after a device I/O failure. It is safe to
// call from the HID reader goroutine; Run delivers the empty-path notification
// and, once the host is configured, reopens even the same hidg device path.
func (m *Manager) Reset() { m.resetEpoch.Add(1) }

type snapshot struct {
	gadget, config, udc string
	links               []string
	attached            bool
}

func (s snapshot) signature() string {
	return strings.Join(append([]string{s.gadget, s.config, s.udc}, s.links...), "\x00")
}

// Run calls onDevice(path) when a HID device is ready, and onDevice("") before
// disconnecting or replacing a session, including a rebind to the same path.
// Callbacks must return promptly. Canceling ctx detaches only our own HID link
// and restores the original UDC binding before Run returns.
func (m *Manager) Run(ctx context.Context, onDevice func(string)) error {
	if onDevice == nil {
		return errors.New("gadget: onDevice callback is required")
	}
	if m.builtinPath == "" {
		m.builtinPath = "/sys/kernel/abk_fido_key"
	}
	if _, err := os.Stat(m.builtinPath); err == nil {
		return errors.New("gadget: old builtin ABK FIDO is active; boot a kernel without that driver first")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gadget: inspect builtin driver: %w", err)
	}
	if m.DeviceRoot == "" {
		m.DeviceRoot = "/dev"
	}
	if m.udcRoot == "" {
		m.udcRoot = "/sys/class/udc"
	}
	if m.PollInterval <= 0 {
		m.PollInterval = 500 * time.Millisecond
	}
	if m.write == nil {
		m.write = writeAttribute
	}
	if m.checkDevice == nil {
		m.checkDevice = checkCharacterDevice
	}
	defer func() {
		m.notify("", "", onDevice)
		m.state.close()
		if err := m.detach(); err != nil {
			log.Printf("gadget: detach: %v", err)
		}
	}()
	ticker := time.NewTicker(m.PollInterval)
	defer ticker.Stop()
	lastError := ""
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := m.reconcile(onDevice)
		if err != nil && err.Error() != lastError {
			log.Printf("gadget: %v", err)
			lastError = err.Error()
			if m.OnError != nil {
				m.OnError(err)
			}
		} else if err == nil && lastError != "" {
			lastError = ""
			if m.OnError != nil {
				m.OnError(nil)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (m *Manager) gadgetRoot() (string, error) {
	if m.root != "" {
		return m.root, nil
	}
	roots := []string{"/config", "/sys/kernel/config"}
	if m.Root != "" {
		roots = []string{m.Root}
	}
	for _, root := range roots {
		path := root
		if filepath.Base(filepath.Clean(root)) != "usb_gadget" {
			path = filepath.Join(root, "usb_gadget")
		}
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			canonical, err := filepath.EvalSymlinks(path)
			if err != nil {
				return "", err
			}
			m.root, err = filepath.Abs(canonical)
			return m.root, err
		}
	}
	return "", errors.New("configfs usb_gadget is not available yet")
}

func readText(path string) (string, error) {
	data, err := os.ReadFile(path)
	return strings.TrimSpace(string(data)), err
}

func (m *Manager) discover() (*snapshot, error) {
	root, err := m.gadgetRoot()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var bound []snapshot
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		gadget := filepath.Join(root, entry.Name())
		udc, err := readText(filepath.Join(gadget, "UDC"))
		if err != nil || udc == "" {
			continue
		}
		bound = append(bound, snapshot{gadget: gadget, udc: udc})
	}
	if len(bound) == 0 {
		return nil, nil
	}
	if len(bound) != 1 {
		return nil, fmt.Errorf("ambiguous USB state: %d bound gadgets; refusing to change any", len(bound))
	}
	s := bound[0]
	configs, err := os.ReadDir(filepath.Join(s.gadget, "configs"))
	if err != nil {
		return nil, err
	}
	var active []snapshot
	for _, config := range configs {
		if !config.IsDir() {
			continue
		}
		candidate := s
		candidate.config = filepath.Join(s.gadget, "configs", config.Name())
		candidate.links, candidate.attached, err = nativeLinks(candidate.config, s.gadget)
		if err != nil {
			return nil, err
		}
		if len(candidate.links) > 0 {
			active = append(active, candidate)
		}
	}
	if len(active) == 0 {
		return nil, nil
	}
	if len(active) != 1 {
		return nil, fmt.Errorf("ambiguous USB state: %d configurations contain native functions; refusing to choose", len(active))
	}
	return &active[0], nil
}

func nativeLinks(config, gadget string) ([]string, bool, error) {
	entries, err := os.ReadDir(config)
	if err != nil {
		return nil, false, err
	}
	var links []string
	attached := false
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink == 0 {
			continue
		}
		path := filepath.Join(config, entry.Name())
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, false, fmt.Errorf("HAL function link is not ready: %w", err)
		}
		if entry.Name() == linkName {
			if filepath.Clean(target) != filepath.Join(gadget, "functions", functionName) {
				return nil, false, errors.New("config link abk_fido belongs to another function")
			}
			attached = true
			continue
		}
		links = append(links, entry.Name()+"="+target)
	}
	sort.Strings(links)
	return links, attached, nil
}

func (m *Manager) reconcile(onDevice func(string)) error {
	if epoch := m.resetEpoch.Load(); epoch != m.seenReset {
		m.seenReset = epoch
		m.notify("", "", onDevice)
		m.failed = ""
		m.failedError = nil
	}
	s, err := m.discover()
	if err != nil || s == nil {
		m.observed = ""
		m.notify("", "", onDevice)
		m.state.close()
		return err
	}
	key := s.signature()
	if !s.attached {
		m.notify("", "", onDevice)
		// Observe one unchanged polling interval before touching a HAL gadget.
		if m.observed != key {
			m.observed = key
			return nil
		}
		if m.failed == key {
			return m.failedError // Keep status, without repeatedly disconnecting ADB.
		}
		if err := m.attach(*s); err != nil {
			m.failed = key
			m.failedError = err
			return err
		}
		m.failed = ""
		m.failedError = nil
	} else if err := m.validateFunction(s.gadget); err != nil {
		m.notify("", "", onDevice)
		return err
	}
	readState := m.readState
	if readState == nil {
		readState = m.state.read
	}
	state, changed, err := readState(filepath.Join(m.udcRoot, s.udc, "state"))
	if err != nil {
		m.notify("", "", onDevice)
		return fmt.Errorf("read UDC connection state: %w", err)
	}
	if changed {
		// sysfs remembers notifications until the open fd is read. A quick
		// disconnect/reconnect may already be configured again by this poll,
		// but it must still cancel the old approval and transport session.
		m.notify("", "", onDevice)
	}
	if state != "configured" {
		m.notify("", "", onDevice)
		return nil
	}
	path, err := m.devicePathFor(s.gadget)
	if err != nil {
		m.notify("", "", onDevice)
		return err
	}
	if err := m.checkDevice(path); err != nil {
		m.notify("", "", onDevice)
		return err
	}
	if err := os.Chmod(path, 0600); err != nil {
		m.notify("", "", onDevice)
		return fmt.Errorf("restrict HID device: %w", err)
	}
	m.notify(key, path, onDevice)
	return nil
}

func (m *Manager) notify(key, path string, callback func(string)) {
	if key == m.deviceKey && path == m.devicePath {
		return
	}
	if m.devicePath != "" {
		callback("")
	}
	m.deviceKey, m.devicePath = key, path
	if path != "" {
		callback(path)
	}
}

func (m *Manager) validateFunction(gadget string) error {
	function := filepath.Join(gadget, "functions", functionName)
	for name, expected := range map[string]string{"protocol": "0", "subclass": "0", "report_length": "64", "no_out_endpoint": "0"} {
		actual, err := readText(filepath.Join(function, name))
		if err != nil || actual != expected {
			return fmt.Errorf("HID function attribute %s is incompatible", name)
		}
	}
	actual, err := os.ReadFile(filepath.Join(function, "report_desc"))
	if err != nil || !bytes.Equal(actual, reportDescriptor) {
		return errors.New("HID function report descriptor is incompatible")
	}
	return nil
}

func (m *Manager) prepareFunction(gadget string) error {
	function := filepath.Join(gadget, "functions", functionName)
	if err := os.Mkdir(function, 0700); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("create standard HID function (kernel must support USB_CONFIGFS_F_HID): %w", err)
		}
		return m.validateFunction(gadget)
	}
	for _, attribute := range []struct{ name, value string }{
		{"protocol", "0\n"}, {"subclass", "0\n"}, {"report_length", "64\n"}, {"no_out_endpoint", "0\n"},
	} {
		if err := m.write(filepath.Join(function, attribute.name), []byte(attribute.value)); err != nil {
			return err
		}
	}
	return m.write(filepath.Join(function, "report_desc"), reportDescriptor)
}

func (m *Manager) attach(s snapshot) error {
	if err := m.prepareFunction(s.gadget); err != nil {
		return err
	}
	current, err := m.discover()
	if err != nil || current == nil || current.signature() != s.signature() || current.attached {
		return errors.New("HAL changed USB configuration before HID attachment; waiting")
	}
	udcPath := filepath.Join(s.gadget, "UDC")
	if err := m.write(udcPath, []byte("\n")); err != nil {
		return fmt.Errorf("temporarily unbind USB: %w", err)
	}
	if m.pause != nil {
		m.pause(100 * time.Millisecond)
	} else {
		time.Sleep(100 * time.Millisecond)
	}
	link := filepath.Join(s.config, linkName)
	created := false
	rollback := func(cause error) error {
		if created {
			if err := os.Remove(link); err != nil && !errors.Is(err, os.ErrNotExist) {
				cause = errors.Join(cause, fmt.Errorf("remove HID link: %w", err))
			}
		}
		if actual, err := readText(udcPath); err == nil && actual == "" {
			if err := m.write(udcPath, []byte(s.udc+"\n")); err != nil {
				cause = errors.Join(cause, fmt.Errorf("restore original USB binding: %w", err))
			}
		}
		return cause
	}
	links, _, err := nativeLinks(s.config, s.gadget)
	if err != nil || strings.Join(links, "\x00") != strings.Join(s.links, "\x00") {
		return rollback(errors.New("HAL changed native USB functions during attachment"))
	}
	if err := os.Symlink(filepath.Join(s.gadget, "functions", functionName), link); err != nil {
		return rollback(fmt.Errorf("link HID function: %w", err))
	}
	created = true
	if err := m.write(udcPath, []byte(s.udc+"\n")); err != nil {
		return rollback(fmt.Errorf("bind USB with HID; original USB configuration restored: %w", err))
	}
	return nil
}

func (m *Manager) devicePathFor(gadget string) (string, error) {
	value, err := readText(filepath.Join(gadget, "functions", functionName, "dev"))
	if err != nil {
		return "", fmt.Errorf("read HID device number: %w", err)
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid HID device number")
	}
	major, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || major == 0 {
		return "", errors.New("invalid HID major number")
	}
	minor, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return "", errors.New("invalid HID minor number")
	}
	return filepath.Join(m.DeviceRoot, fmt.Sprintf("hidg%d", minor)), nil
}

func checkCharacterDevice(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("%s is not a character device", path)
	}
	return nil
}

func writeAttribute(path string, value []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	n, writeErr := file.Write(value)
	if writeErr == nil && n != len(value) {
		writeErr = io.ErrShortWrite
	}
	return errors.Join(writeErr, file.Close())
}

// detach deliberately leaves the unlinked function instance in configfs: HAL
// may still hold a reference. A future start can validate and reuse it safely.
func (m *Manager) detach() error {
	if m.root == "" {
		return nil
	}
	entries, err := os.ReadDir(m.root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		gadget := filepath.Join(m.root, entry.Name())
		configs, err := os.ReadDir(filepath.Join(gadget, "configs"))
		if err != nil {
			continue
		}
		for _, config := range configs {
			if !config.IsDir() {
				continue
			}
			path := filepath.Join(gadget, "configs", config.Name())
			_, attached, err := nativeLinks(path, gadget)
			if err != nil || !attached || m.validateFunction(gadget) != nil {
				continue
			}
			udcPath := filepath.Join(gadget, "UDC")
			udc, err := readText(udcPath)
			if err != nil {
				return err
			}
			if udc != "" {
				if err := m.write(udcPath, []byte("\n")); err != nil {
					return err
				}
				if m.pause != nil {
					m.pause(100 * time.Millisecond)
				} else {
					time.Sleep(100 * time.Millisecond)
				}
			}
			removeErr := os.Remove(filepath.Join(path, linkName))
			if udc != "" {
				if err := m.write(udcPath, []byte(udc+"\n")); err != nil {
					return errors.Join(removeErr, err)
				}
			}
			if removeErr != nil {
				return removeErr
			}
		}
	}
	return nil
}
