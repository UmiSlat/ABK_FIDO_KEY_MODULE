// Package control exposes a bounded, root-only Unix socket. It is deliberately
// separate from the USB parser: management and approvals must remain available
// while the authenticator waits for the companion's biometric prompt.
package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/UmiSlat/abk-fido-daemon/internal/authenticator"
	"github.com/UmiSlat/abk-fido-daemon/internal/ctaphid"
)

const MaxRequest = 65536

type Request struct {
	Op         string `json:"op"`
	Session    string `json:"session,omitempty"`
	Data       string `json:"data,omitempty"`
	Epoch      string `json:"epoch,omitempty"`
	Generation uint64 `json:"generation,omitempty"`
	ID         int    `json:"id,omitempty"`
	Allow      bool   `json:"allow,omitempty"`
	TimeoutMS  int    `json:"timeout_ms,omitempty"`
}

type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Data  any    `json:"data,omitempty"`
}

type localSession struct {
	server  *ctaphid.Server
	packets chan []byte
	touched time.Time
	closed  chan struct{}
}

type Server struct {
	Engine *authenticator.Engine
	Broker *Broker
	// AllowedUID is initialized by New to the server's uid (root on Android).
	AllowedUID  uint32
	epoch       string
	mu          sync.Mutex
	sessions    map[string]*localSession
	bound       bool
	hidDevice   string
	usbError    string
	gadgetError string
	closed      bool
}

func New(engine *authenticator.Engine, broker *Broker) (*Server, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &Server{Engine: engine, Broker: broker, AllowedUID: uint32(os.Geteuid()), epoch: hex.EncodeToString(nonce[:]), sessions: make(map[string]*localSession)}, nil
}

func (s *Server) SetUSB(path string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bound, s.hidDevice = path != "", filepath.Base(path)
	if path == "" {
		s.hidDevice = ""
	}
	if err != nil {
		s.usbError = err.Error()
	} else {
		s.usbError = ""
	}
}

func (s *Server) SetGadgetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		s.gadgetError = ""
	} else {
		s.gadgetError = err.Error()
	}
}

func (s *Server) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	old := s.sessions
	s.sessions = make(map[string]*localSession)
	for _, v := range old {
		close(v.closed)
	}
	s.mu.Unlock()
	for _, v := range old {
		v.server.Close()
	}
}

func (s *Server) Serve(ctx context.Context, path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return errors.New("control path is not a socket")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	defer ln.Close()
	defer os.Remove(path)
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	var wg sync.WaitGroup
	defer wg.Wait()
	go func() { <-ctx.Done(); ln.Close() }()
	// Limit outstanding control connections, including blocking HID reads.
	sem := make(chan struct{}, 32)
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); defer func() { <-sem }(); defer conn.Close(); s.handleConn(ctx, conn) }()
	}
}

func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	if err := checkPeer(conn, s.AllowedUID); err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(45 * time.Second))
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	raw, err := io.ReadAll(io.LimitReader(conn, MaxRequest+1))
	if err != nil || len(raw) > MaxRequest {
		json.NewEncoder(conn).Encode(Response{Error: "request too large or incomplete"})
		return
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		json.NewEncoder(conn).Encode(Response{Error: "invalid request"})
		return
	}
	// One request per connection; trailing JSON or junk is never another command.
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		json.NewEncoder(conn).Encode(Response{Error: "trailing request data"})
		return
	}
	data, err := s.Dispatch(ctx, req)
	resp := Response{OK: err == nil, Data: data}
	if err != nil {
		resp.Error = err.Error()
		resp.Data = nil
	}
	json.NewEncoder(conn).Encode(resp)
}

func checkPeer(conn *net.UnixConn, uid uint32) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var credential *syscall.Ucred
	var sockErr error
	if err = raw.Control(func(fd uintptr) {
		credential, sockErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if sockErr != nil {
		return sockErr
	}
	if credential == nil || credential.Uid != uid {
		return errors.New("root control client required")
	}
	return nil
}

var sessionPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

func (s *Server) session(id string) (*localSession, error) {
	if !sessionPattern.MatchString(id) {
		return nil, errors.New("invalid session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("service closed")
	}
	// Expire abandoned sessions, cancelling approvals and continuations too.
	for key, v := range s.sessions {
		if time.Since(v.touched) > 2*time.Minute {
			delete(s.sessions, key)
			close(v.closed)
			go v.server.Close()
		}
	}
	if v := s.sessions[id]; v != nil {
		v.touched = time.Now()
		return v, nil
	}
	if len(s.sessions) >= 16 {
		return nil, errors.New("too many local sessions")
	}
	// A 7609-byte PING response occupies 129 reports; local clients begin
	// reading after the final write returns. Bound the queue above that size.
	v := &localSession{packets: make(chan []byte, 256), closed: make(chan struct{}), touched: time.Now()}
	v.server = ctaphid.New(func(ctx context.Context, cid uint32, payload []byte) []byte {
		return s.Engine.Execute(ctx, "local:"+s.epoch+":"+id, cid, payload)
	}, func(packet []byte) error {
		select {
		case <-v.closed:
			return errors.New("session closed")
		default:
		}
		select {
		case v.packets <- append([]byte(nil), packet...):
			return nil
		default:
			return errors.New("response queue full")
		}
	})
	s.sessions[id] = v
	return v, nil
}

func (s *Server) Dispatch(ctx context.Context, r Request) (any, error) {
	switch r.Op {
	case "status":
		st := s.Engine.Status()
		s.mu.Lock()
		defer s.mu.Unlock()
		usbError := s.usbError
		if s.gadgetError != "" {
			usbError = s.gadgetError
		}
		return map[string]any{"backend": "userspace", "protocol": 1, "epoch": s.epoch, "credential_count": st.CredentialCount, "store_generation": st.Generation, "last_error": st.LastError, "last_trace": st.LastTrace, "usb_error": usbError, "bound": s.bound, "hid_dev": s.hidDevice, "auth_gate_enabled": true}, nil
	case "auth-pending":
		return s.Broker.Pending(), nil
	case "auth-decision":
		return nil, s.Broker.Decide(r.ID, r.Allow)
	case "store-get":
		blob, gen, err := s.Engine.Snapshot()
		if err != nil {
			return nil, err
		}
		return map[string]any{"blob": base64.StdEncoding.EncodeToString(blob), "generation": gen, "epoch": s.epoch}, nil
	case "store-put":
		if r.Epoch != s.epoch || r.Generation == 0 {
			return nil, errors.New("stale store snapshot")
		}
		blob, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil {
			return nil, err
		}
		if err = s.Engine.Replace(blob, r.Generation); err != nil {
			return nil, err
		}
		return map[string]any{"generation": s.Engine.Status().Generation}, nil
	case "hid-write":
		packet, err := base64.StdEncoding.DecodeString(r.Data)
		if err != nil || len(packet) != 64 {
			return nil, errors.New("expected one 64-byte packet")
		}
		v, err := s.session(r.Session)
		if err != nil {
			return nil, err
		}
		return nil, v.server.Handle(packet)
	case "hid-read":
		v, err := s.session(r.Session)
		if err != nil {
			return nil, err
		}
		timeout := r.TimeoutMS
		if timeout <= 0 || timeout > 40000 {
			timeout = 40000
		}
		timer := time.NewTimer(time.Duration(timeout) * time.Millisecond)
		defer timer.Stop()
		select {
		case packet := <-v.packets:
			return map[string]string{"packet": base64.StdEncoding.EncodeToString(packet)}, nil
		case <-v.closed:
			return nil, errors.New("session closed")
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
			return nil, errors.New("HID read timed out")
		}
	case "hid-close":
		s.mu.Lock()
		v := s.sessions[r.Session]
		delete(s.sessions, r.Session)
		if v != nil {
			close(v.closed)
		}
		s.mu.Unlock()
		if v != nil {
			v.server.Close()
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("unknown operation %q", r.Op)
	}
}
