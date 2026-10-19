package gadget

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// The USB UDC core calls sysfs_notify("state") on bus resets and state
// transitions. Keeping the fd open lets POLLPRI detect even transitions that
// finish between two manager polls; reopening the file each time loses them.
type udcStateWatcher struct {
	path  string
	file  *os.File
	state string
}

func (w *udcStateWatcher) close() {
	if w.file != nil {
		w.file.Close()
	}
	w.file, w.path, w.state = nil, "", ""
}

func (w *udcStateWatcher) read(path string) (state string, changed bool, err error) {
	if w.path != path || w.file == nil {
		w.close()
		w.file, err = os.Open(path)
		if err != nil {
			return "", false, err
		}
		w.path = path
	} else {
		fd := int(w.file.Fd())
		var priority syscall.FdSet
		if fd < 0 || fd >= len(priority.Bits)*64 {
			w.close()
			return "", false, errors.New("UDC state fd exceeds select limit")
		}
		priority.Bits[fd/64] |= 1 << uint(fd%64)
		zero := syscall.Timeval{}
		count, selectErr := syscall.Select(fd+1, nil, nil, &priority, &zero)
		if selectErr != nil {
			w.close()
			return "", false, selectErr
		}
		changed = count > 0
		if !changed {
			// Do not acknowledge kernfs here: a reset notification could
			// arrive after select but before a read and would otherwise be
			// consumed without replacing the old transport session.
			return w.state, false, nil
		}
	}
	// A rewind plus read acknowledges the current kernfs event counter.
	if _, err = w.file.Seek(0, io.SeekStart); err != nil {
		w.close()
		return "", changed, err
	}
	data, err := io.ReadAll(io.LimitReader(w.file, 256))
	if err != nil || len(data) == 256 {
		w.close()
		return "", changed, errors.Join(err, fmt.Errorf("invalid UDC state response"))
	}
	w.state = strings.TrimSpace(string(data))
	return w.state, changed, nil
}
