package control

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"

	"github.com/UmiSlat/abk-fido-daemon/internal/ctaphid"
)

type USB struct {
	Control *Server
	Reset   func()
	mu      sync.Mutex
	cancel  context.CancelFunc
	done    chan struct{}
}

// Attach is called on every USB connection generation, even when hidgN is
// unchanged. Old approvals and packets are cancelled before a new session.
func (u *USB) Attach(parent context.Context, path string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cancel != nil {
		u.cancel()
		<-u.done
		u.cancel = nil
	}
	u.Control.SetUSB("", nil)
	if path == "" || parent.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	u.cancel, u.done = cancel, make(chan struct{})
	done := u.done
	go func() {
		defer close(done)
		if err := u.run(ctx, path); err != nil && ctx.Err() == nil {
			u.Control.SetUSB("", err)
			if u.Reset != nil {
				u.Reset()
			}
		}
	}()
}

func (u *USB) Close() { u.Attach(context.Background(), "") }

func (u *USB) run(ctx context.Context, path string) error {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	session := "usb:" + hex.EncodeToString(nonce[:])
	packets := make(chan []byte, 256)
	server := ctaphid.New(func(c context.Context, cid uint32, payload []byte) []byte {
		return u.Control.Engine.Execute(c, session, cid, payload)
	}, func(packet []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		select {
		case packets <- append([]byte(nil), packet...):
			return nil
		default:
			return errors.New("USB output queue full")
		}
	})
	defer server.Close()
	u.Control.SetUSB(path, nil)
	var outgoing []byte
	var writeSince time.Time
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		if outgoing == nil {
			select {
			case outgoing = <-packets:
				writeSince = time.Now()
			default:
			}
		}
		if outgoing != nil {
			n, writeErr := syscall.Write(fd, outgoing)
			if writeErr == nil {
				if n != 64 {
					return fmt.Errorf("short HID write: %d", n)
				}
				outgoing = nil
			} else if writeErr != syscall.EAGAIN && writeErr != syscall.EINTR {
				return writeErr
			} else if time.Since(writeSince) > 2*time.Second {
				return errors.New("USB host stopped reading")
			}
		}
		var packet [64]byte
		n, readErr := syscall.Read(fd, packet[:])
		if readErr == nil && n > 0 {
			if n != 64 {
				return fmt.Errorf("short HID report: %d", n)
			}
			if err := server.Handle(packet[:]); err != nil {
				return err
			}
			continue
		}
		if readErr != nil && readErr != syscall.EAGAIN && readErr != syscall.EINTR {
			return readErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
