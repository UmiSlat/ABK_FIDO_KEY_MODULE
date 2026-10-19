package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/UmiSlat/abk-fido-daemon/internal/authenticator"
	"github.com/UmiSlat/abk-fido-daemon/internal/control"
	"github.com/UmiSlat/abk-fido-daemon/internal/gadget"
)

var version = "0.4.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: abk-fidod serve|ctl|version")
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "ctl":
		f := flag.NewFlagSet("ctl", flag.ContinueOnError)
		socket := f.String("socket", "/data/adb/abk-fido/control.sock", "control socket")
		if err := f.Parse(args[1:]); err != nil {
			return err
		}
		if f.NArg() != 1 {
			return errors.New("ctl expects a base64-encoded JSON request")
		}
		encoded := f.Arg(0)
		if len(encoded) > control.MaxRequest*2 {
			return errors.New("request too large")
		}
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return err
		}
		if len(raw) > control.MaxRequest {
			return errors.New("request too large")
		}
		var req control.Request
		if err = json.Unmarshal(raw, &req); err != nil {
			return err
		}
		data, err := control.Call(context.Background(), *socket, req)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil
	case "serve":
		return serve(args[1:])
	default:
		return errors.New("unknown command")
	}
}

func serve(args []string) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	state := f.String("state-dir", "/data/adb/abk-fido", "private runtime directory")
	store := f.String("store", "/data/adb/abk-fido/store.bin", "compatible persistent credential store")
	legacyStore := f.String("legacy-store", "/metadata/abk_fido_store.bin", "import this legacy store once if the destination is missing; empty disables import")
	root := f.String("gadget-root", "", "USB configfs gadget root (autodetected by default)")
	noUSB := f.Bool("no-usb", false, "serve local CTAP clients without changing USB")
	if err := f.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("serve requires root")
	}
	if _, err := os.Stat("/sys/kernel/abk_fido_key"); err == nil {
		return errors.New("legacy FIDO is built into this kernel; first boot a kernel without it")
	}
	if err := privateDirectory(*state); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(*state, "serve.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another FIDO service is running")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	broker := &control.Broker{}
	if *legacyStore != "" {
		if err := authenticator.MigrateLegacy(*store, *legacyStore); err != nil {
			return err
		}
	}
	engine, err := authenticator.New(*store, broker.Approve)
	if err != nil {
		return err
	}
	server, err := control.New(engine, broker)
	if err != nil {
		return err
	}
	usb := &control.USB{Control: server}
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait(); usb.Close(); server.Close() }()
	if !*noUSB {
		manager := &gadget.Manager{Root: *root}
		manager.OnError = server.SetGadgetError
		usb.Reset = manager.Reset
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := manager.Run(ctx, func(path string) { usb.Attach(ctx, path) }); err != nil {
				server.SetUSB("", err)
				log.Printf("USB unavailable: %v", err)
			}
		}()
	}
	log.Printf("ABK FIDO %s: userspace authenticator started", version)
	return server.Serve(ctx, filepath.Join(*state, "control.sock"))
}

func privateDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("runtime path must be a real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return errors.New("runtime directory must belong to root")
	}
	return os.Chmod(path, 0700)
}
