package gadget

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	m      *Manager
	gadget string
	config string
	udc    string
	dev    string
	events []string
	writes []string
}

func put(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{gadget: filepath.Join(root, "usb_gadget", "g1"), dev: filepath.Join(root, "dev", "hidg2")}
	f.config = filepath.Join(f.gadget, "configs", "b.1")
	f.udc = filepath.Join(f.gadget, "UDC")
	put(t, f.udc, "test.dwc3\n")
	put(t, filepath.Join(f.gadget, "idVendor"), "0x18d1\n")
	put(t, filepath.Join(f.gadget, "idProduct"), "0x4e11\n")
	if err := os.MkdirAll(filepath.Join(f.gadget, "functions", "ffs.adb"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.config, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.gadget, "functions", "ffs.adb"), filepath.Join(f.config, "f1")); err != nil {
		t.Fatal(err)
	}
	udcRoot := filepath.Join(root, "udc")
	put(t, filepath.Join(udcRoot, "test.dwc3", "state"), "configured\n")
	put(t, f.dev, "")
	f.m = &Manager{
		Root: root, DeviceRoot: filepath.Dir(f.dev), udcRoot: udcRoot,
		builtinPath: filepath.Join(root, "absent-builtin"),
		checkDevice: func(path string) error { _, err := os.Stat(path); return err },
		pause:       func(time.Duration) {},
		// Regular fixture files do not issue kernfs POLLPRI notifications.
		readState: func(path string) (string, bool, error) {
			state, err := readText(path)
			return state, false, err
		},
	}
	f.m.write = func(path string, value []byte) error {
		f.writes = append(f.writes, path+"="+string(value))
		// A real configfs HID instance exposes these files immediately after
		// mkdir. The fixture uses regular files and models the allocated minor.
		if filepath.Base(path) == "report_desc" {
			put(t, filepath.Join(filepath.Dir(path), "dev"), "240:2\n")
		}
		return os.WriteFile(path, value, 0600)
	}
	t.Cleanup(f.m.state.close)
	return f
}

func TestStateWatcherDoesNotAcknowledgeEventsAfterAnEmptyPoll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	put(t, path, "configured\n")
	var watcher udcStateWatcher
	defer watcher.close()
	state, changed, err := watcher.read(path)
	if err != nil || changed || state != "configured" {
		t.Fatal(state, changed, err)
	}
	// A regular file has no POLLPRI. Without a notification, the watcher must
	// use cached state rather than seek/read and accidentally acknowledge a
	// sysfs notification that races with select returning zero.
	put(t, path, "not attached\n")
	state, changed, err = watcher.read(path)
	if err != nil || changed || state != "configured" {
		t.Fatal("read acknowledged a state change after an empty poll", state, changed, err)
	}
}

func (f *fixture) callback(path string) { f.events = append(f.events, path) }

func (f *fixture) ready(t *testing.T) {
	t.Helper()
	for i := 0; i < 2; i++ {
		if err := f.m.reconcile(f.callback); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAttachPreservesNativeUSBAndIsIdempotent(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	if !reflect.DeepEqual(f.events, []string{f.dev}) {
		t.Fatal(f.events)
	}
	if value, _ := readText(f.udc); value != "test.dwc3" {
		t.Fatal(value)
	}
	for name, expected := range map[string]string{"idVendor": "0x18d1", "idProduct": "0x4e11"} {
		if value, _ := readText(filepath.Join(f.gadget, name)); value != expected {
			t.Fatalf("%s changed: %s", name, value)
		}
	}
	if target, _ := os.Readlink(filepath.Join(f.config, "f1")); !strings.HasSuffix(target, "ffs.adb") {
		t.Fatal("ADB link changed", target)
	}
	info, err := os.Stat(f.dev)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("HID device is not private", err)
	}
	writes := len(f.writes)
	for i := 0; i < 5; i++ {
		if err := f.m.reconcile(f.callback); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.writes) != writes || len(f.events) != 1 {
		t.Fatal("unchanged gadget was rebound", f.writes, f.events)
	}
}

func TestErrorCallbackReportsChangesAndRecovery(t *testing.T) {
	f := newFixture(t)
	other := filepath.Join(filepath.Dir(f.gadget), "g2")
	put(t, filepath.Join(other, "UDC"), "other.dwc3\n")
	f.m.PollInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var reports []error
	f.m.OnError = func(err error) {
		reports = append(reports, err)
		if err != nil {
			if removeErr := os.RemoveAll(other); removeErr != nil {
				t.Fatal(removeErr)
			}
		} else {
			cancel()
		}
	}
	if err := f.m.Run(ctx, f.callback); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0] == nil || !strings.Contains(reports[0].Error(), "ambiguous") || reports[1] != nil {
		t.Fatal("missing error or recovery status", reports)
	}
}

func TestHostDisconnectReconnectAndResetReplaceSession(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	state := filepath.Join(f.m.udcRoot, "test.dwc3", "state")
	put(t, state, "not attached\n")
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	put(t, state, "configured\n")
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	f.m.Reset()
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	want := []string{f.dev, "", f.dev, "", f.dev}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatalf("%q != %q", f.events, want)
	}
}

func TestFastStateTransitionCancelsSessionEvenWhenAlreadyConfigured(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	changed := true
	f.m.readState = func(path string) (string, bool, error) {
		state, err := readText(path)
		event := changed
		changed = false
		return state, event, err
	}
	// The disconnect and reset happened between polls; the visible state is
	// configured both before and after. A queued sysfs notification is enough.
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.events, []string{f.dev, "", f.dev}) {
		t.Fatal("fast reconnect reused an old request session", f.events)
	}
}

func TestHALReconfigurationAddsHIDToNewNativeSet(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	put(t, f.udc, "\n")
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.config, linkName)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.config, "f1")); err != nil {
		t.Fatal(err)
	}
	mtp := filepath.Join(f.gadget, "functions", "mtp.gs0")
	if err := os.Mkdir(mtp, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mtp, filepath.Join(f.config, "f2")); err != nil {
		t.Fatal(err)
	}
	put(t, f.udc, "test.dwc3\n")
	f.ready(t)
	if !reflect.DeepEqual(f.events, []string{f.dev, "", f.dev}) {
		t.Fatal(f.events)
	}
	if target, _ := os.Readlink(filepath.Join(f.config, "f2")); target != mtp {
		t.Fatal(target)
	}
}

func TestFailedHIDBindRestoresADBWithoutRetryLoop(t *testing.T) {
	f := newFixture(t)
	write := f.m.write
	f.m.write = func(path string, value []byte) error {
		if path == f.udc && strings.TrimSpace(string(value)) != "" {
			if _, err := os.Lstat(filepath.Join(f.config, linkName)); err == nil {
				return errors.New("simulated endpoint exhaustion")
			}
		}
		return write(path, value)
	}
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	if err := f.m.reconcile(f.callback); err == nil {
		t.Fatal("bind unexpectedly succeeded")
	}
	if value, _ := readText(f.udc); value != "test.dwc3" {
		t.Fatal("ADB was left disconnected", value)
	}
	if _, err := os.Lstat(filepath.Join(f.config, linkName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	writes := len(f.writes)
	for i := 0; i < 5; i++ {
		if err := f.m.reconcile(f.callback); err == nil || !strings.Contains(err.Error(), "simulated endpoint exhaustion") {
			t.Fatal("failed bind error disappeared without recovery", err)
		}
	}
	if len(f.writes) != writes || len(f.events) != 0 {
		t.Fatal("failed bind retry loop", f.writes, f.events)
	}
}

func TestAmbiguousConfigurationsAndGadgetsAreNeverModified(t *testing.T) {
	for _, kind := range []string{"config", "gadget"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if kind == "gadget" {
				put(t, filepath.Join(filepath.Dir(f.gadget), "g2", "UDC"), "other.dwc3\n")
			} else {
				config := filepath.Join(f.gadget, "configs", "b.2")
				if err := os.Mkdir(config, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(f.gadget, "functions", "ffs.adb"), filepath.Join(config, "f1")); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.m.reconcile(f.callback); err == nil || !strings.Contains(err.Error(), "ambiguous") {
				t.Fatal(err)
			}
			if len(f.writes) != 0 {
				t.Fatal("ambiguous configuration modified", f.writes)
			}
		})
	}
}

func TestRefuseBuiltinAndForeignFunction(t *testing.T) {
	f := newFixture(t)
	if err := os.Mkdir(f.m.builtinPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Run(context.Background(), f.callback); err == nil || !strings.Contains(err.Error(), "builtin") {
		t.Fatal(err)
	}
	if len(f.writes) != 0 {
		t.Fatal(f.writes)
	}
	function := filepath.Join(f.gadget, "functions", functionName)
	if err := os.Mkdir(function, 0700); err != nil {
		t.Fatal(err)
	}
	put(t, filepath.Join(function, "protocol"), "1\n")
	if err := f.m.reconcile(f.callback); err != nil {
		t.Fatal(err)
	}
	if err := f.m.reconcile(f.callback); err == nil {
		t.Fatal("foreign HID instance accepted")
	}
	if len(f.writes) != 0 {
		t.Fatal("foreign instance changed", f.writes)
	}
}

func TestCancellationDetachesOnlyOurLinkAndRestoresUSB(t *testing.T) {
	f := newFixture(t)
	f.m.PollInterval = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := f.m.Run(ctx, func(path string) {
		f.callback(path)
		if path != "" {
			cancel()
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.events, []string{f.dev, ""}) {
		t.Fatal(f.events)
	}
	if _, err := os.Lstat(filepath.Join(f.config, linkName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(f.config, "f1")); err != nil {
		t.Fatal("ADB link removed", err)
	}
	if value, _ := readText(f.udc); value != "test.dwc3" {
		t.Fatal(value)
	}
}

func TestMalformedDeviceNumberCannotEscapeDeviceRoot(t *testing.T) {
	f := newFixture(t)
	f.ready(t)
	for _, value := range []string{"240:../secret", "0:0", "240:-1", "240:65536", "240:2:1"} {
		put(t, filepath.Join(f.gadget, "functions", functionName, "dev"), value)
		if _, err := f.m.devicePathFor(f.gadget); err == nil {
			t.Fatal(value)
		}
	}
}
