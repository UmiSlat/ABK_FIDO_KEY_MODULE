package ctaphid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"
)

type replies struct{ reports chan []byte }

func makeServer(t *testing.T, handler Handler) (*Server, *replies) {
	t.Helper()
	r := &replies{reports: make(chan []byte, 1024)}
	config := defaultTiming
	config.keepalive = 5 * time.Millisecond
	config.maintenance = 5 * time.Millisecond
	s := newServer(handler, func(p []byte) error { r.reports <- bytes.Clone(p); return nil }, config)
	t.Cleanup(s.Close)
	return s, r
}

func frame(cid uint32, command byte, payload []byte) [][]byte {
	var out [][]byte
	position, sequence := 0, byte(0)
	for first := true; first || position < len(payload); first = false {
		p := make([]byte, 64)
		binary.BigEndian.PutUint32(p, cid)
		start := 5
		if first {
			p[4] = command | 0x80
			binary.BigEndian.PutUint16(p[5:7], uint16(len(payload)))
			start = 7
		} else {
			p[4] = sequence
			sequence++
		}
		position += copy(p[start:], payload[position:])
		out = append(out, p)
	}
	return out
}

func send(t *testing.T, s *Server, cid uint32, command byte, payload []byte) {
	t.Helper()
	for _, p := range frame(cid, command, payload) {
		if err := s.Handle(p); err != nil {
			t.Fatal(err)
		}
	}
}

func (r *replies) next(t *testing.T) (uint32, byte, []byte) {
	t.Helper()
	var first []byte
	select {
	case first = <-r.reports:
	case <-time.After(time.Second):
		t.Fatal("response timeout")
	}
	if len(first) != 64 || first[4]&0x80 == 0 {
		t.Fatalf("invalid initialization report: %x", first)
	}
	cid, command, length := binary.BigEndian.Uint32(first), first[4]&0x7f, int(binary.BigEndian.Uint16(first[5:7]))
	data := append([]byte(nil), first[7:7+min(57, length)]...)
	for sequence := byte(0); len(data) < length; sequence++ {
		var p []byte
		select {
		case p = <-r.reports:
		case <-time.After(time.Second):
			t.Fatal("continuation timeout")
		}
		if binary.BigEndian.Uint32(p) != cid || p[4] != sequence {
			t.Fatalf("bad continuation: %x", p)
		}
		data = append(data, p[5:5+min(59, length-len(data))]...)
	}
	return cid, command, data
}

func allocate(t *testing.T, s *Server, r *replies) uint32 {
	t.Helper()
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	send(t, s, BroadcastCID, CommandInit, nonce)
	wire, cmd, body := r.next(t)
	if wire != BroadcastCID || cmd != CommandInit || len(body) != 17 || !bytes.Equal(body[:8], nonce) {
		t.Fatalf("bad INIT response: %x/%x/%x", wire, cmd, body)
	}
	cid := binary.BigEndian.Uint32(body[8:12])
	if cid == 0 || cid == BroadcastCID || body[12] != 2 || body[16] != 0x0d {
		t.Fatalf("bad INIT fields: %x", body)
	}
	return cid
}

func expectError(t *testing.T, r *replies, cid uint32, code byte) {
	t.Helper()
	wire, cmd, body := r.next(t)
	if wire != cid || cmd != CommandError || !bytes.Equal(body, []byte{code}) {
		t.Fatalf("want error cid=%x code=%x, got %x/%x/%x", cid, code, wire, cmd, body)
	}
}

func nextCBOR(t *testing.T, r *replies, cid uint32) []byte {
	t.Helper()
	for {
		wire, cmd, data := r.next(t)
		if wire != cid {
			t.Fatalf("wrong response CID: %x", wire)
		}
		if cmd == CommandKeepalive {
			continue
		}
		if cmd != CommandCBOR {
			t.Fatalf("expected CBOR, got %x", cmd)
		}
		return data
	}
}

func TestInitPingWinkAndMaximumFraming(t *testing.T) {
	s, r := makeServer(t, nil)
	cid := allocate(t, s, r)
	for _, size := range []int{0, 1, 57, 58, 116, MaxMessageSize} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i * 31)
		}
		send(t, s, cid, CommandPing, payload)
		wire, cmd, got := r.next(t)
		if wire != cid || cmd != CommandPing || !bytes.Equal(got, payload) {
			t.Fatalf("PING size%d mismatch", size)
		}
	}
	send(t, s, cid, CommandWink, nil)
	_, cmd, got := r.next(t)
	if cmd != CommandWink || len(got) != 0 {
		t.Fatal("invalid WINK response")
	}
}

func TestProtocolErrorsAndSequenceIsolation(t *testing.T) {
	s, r := makeServer(t, nil)
	cid := allocate(t, s, r)
	other := allocate(t, s, r)
	if !errors.Is(s.Handle(make([]byte, 63)), ErrInvalidReport) {
		t.Fatal("short report accepted")
	}
	send(t, s, 0, CommandPing, nil)
	expectError(t, r, 0, ErrorInvalidChannel)
	send(t, s, BroadcastCID, CommandPing, nil)
	expectError(t, r, BroadcastCID, ErrorInvalidChannel)
	send(t, s, cid, 0x03, nil)
	expectError(t, r, cid, ErrorInvalidCommand)
	send(t, s, cid, CommandCBOR, nil)
	expectError(t, r, cid, ErrorInvalidLength)
	send(t, s, cid, CommandWink, []byte{1})
	expectError(t, r, cid, ErrorInvalidLength)
	bad := frame(cid, CommandPing, nil)[0]
	binary.BigEndian.PutUint16(bad[5:7], MaxMessageSize+1)
	if err := s.Handle(bad); err != nil {
		t.Fatal(err)
	}
	expectError(t, r, cid, ErrorInvalidLength)
	packets := frame(cid, CommandPing, make([]byte, 120))
	if err := s.Handle(packets[0]); err != nil {
		t.Fatal(err)
	}
	send(t, s, other, CommandPing, nil)
	expectError(t, r, other, ErrorChannelBusy)
	packets[1][4] = 1
	if err := s.Handle(packets[1]); err != nil {
		t.Fatal(err)
	}
	expectError(t, r, cid, ErrorInvalidSequence)
	send(t, s, cid, CommandPing, []byte("recovered"))
	_, _, got := r.next(t)
	if string(got) != "recovered" {
		t.Fatal("sequence error poisoned channel")
	}
}

func TestCBORHandlerCopiesInputAndSplitsOutput(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	request := bytes.Repeat([]byte{0x19}, 120)
	want := bytes.Repeat([]byte{0x42}, MaxMessageSize)
	s, r := makeServer(t, func(ctx context.Context, cid uint32, p []byte) []byte {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil
		}
		if !bytes.Equal(p, request) {
			return []byte{0x7f}
		}
		return want
	})
	cid := allocate(t, s, r)
	packets := frame(cid, CommandCBOR, request)
	for _, p := range packets {
		if err := s.Handle(p); err != nil {
			t.Fatal(err)
		}
		clear(p)
	}
	<-entered
	close(release)
	if got := nextCBOR(t, r, cid); !bytes.Equal(got, want) {
		t.Fatal("response/input buffer mismatch")
	}
}

func TestBusyKeepaliveAndCancelWhileHandlerRuns(t *testing.T) {
	started := make(chan struct{})
	s, r := makeServer(t, func(ctx context.Context, _ uint32, _ []byte) []byte {
		SetKeepaliveStatus(ctx, KeepaliveUpNeeded)
		close(started)
		<-ctx.Done()
		return []byte{0}
	})
	cid := allocate(t, s, r)
	other := allocate(t, s, r)
	send(t, s, cid, CommandCBOR, []byte{1})
	<-started
	for {
		wire, cmd, p := r.next(t)
		if wire == cid && cmd == CommandKeepalive {
			if !bytes.Equal(p, []byte{KeepaliveUpNeeded}) {
				t.Fatalf("wrong keepalive: %x", p)
			}
			break
		}
	}
	send(t, s, other, CommandPing, nil)
	for {
		wire, cmd, p := r.next(t)
		if cmd == CommandKeepalive {
			continue
		}
		if wire != other || cmd != CommandError || !bytes.Equal(p, []byte{ErrorChannelBusy}) {
			t.Fatal("missing busy response")
		}
		break
	}
	send(t, s, cid, CommandCancel, nil)
	if got := nextCBOR(t, r, cid); !bytes.Equal(got, []byte{0x2d}) {
		t.Fatalf("cancel status: %x", got)
	}
}

func TestInitResyncDiscardsCanceledHandlerResponse(t *testing.T) {
	started := make(chan struct{})
	returned := make(chan struct{})
	s, r := makeServer(t, func(ctx context.Context, _ uint32, _ []byte) []byte {
		close(started)
		<-ctx.Done()
		close(returned)
		return []byte{0, 0x44}
	})
	cid := allocate(t, s, r)
	send(t, s, cid, CommandCBOR, []byte{1})
	<-started
	nonce := []byte{8, 7, 6, 5, 4, 3, 2, 1}
	send(t, s, cid, CommandInit, nonce)
	for {
		wire, cmd, p := r.next(t)
		if cmd == CommandKeepalive {
			continue
		}
		if wire != cid || cmd != CommandInit || !bytes.Equal(p[:8], nonce) || binary.BigEndian.Uint32(p[8:12]) != cid {
			t.Fatal("resync mismatch")
		}
		break
	}
	<-returned
	s.Close()
	for {
		select {
		case p := <-r.reports:
			if p[4] == 0x80|CommandCBOR {
				t.Fatal("stale response survived resync")
			}
		default:
			return
		}
	}
}

func TestFragmentTimeoutAndIdleChannelEviction(t *testing.T) {
	s, r := makeServer(t, nil)
	cid := allocate(t, s, r)
	if err := s.Handle(frame(cid, CommandPing, make([]byte, 58))[0]); err != nil {
		t.Fatal(err)
	}
	s.expire(time.Now().Add(4 * time.Second))
	expectError(t, r, cid, ErrorMessageTimeout)
	for range MaxChannels + 10 {
		allocate(t, s, r)
	}
	s.mu.Lock()
	count := len(s.channels)
	_, oldExists := s.channels[cid]
	s.mu.Unlock()
	if count > MaxChannels || oldExists {
		t.Fatalf("channel limit/LRU failed: %d/%v", count, oldExists)
	}
	s.expire(time.Now().Add(6 * time.Minute))
	s.mu.Lock()
	count = len(s.channels)
	s.mu.Unlock()
	if count != 0 {
		t.Fatal("idle channels were not expired")
	}
}

func TestOperationTimeoutAndHandlerFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler Handler
		want    byte
	}{
		{"timeout", func(ctx context.Context, _ uint32, _ []byte) []byte { <-ctx.Done(); return []byte{0} }, 0x2f},
		{"panic", func(context.Context, uint32, []byte) []byte { panic("bad request") }, 0x7f},
		{"empty", func(context.Context, uint32, []byte) []byte { return nil }, 0x7f},
		{"oversize", func(context.Context, uint32, []byte) []byte { return make([]byte, MaxMessageSize+1) }, 0x7f},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &replies{reports: make(chan []byte, 1024)}
			config := defaultTiming
			config.operation = 20 * time.Millisecond
			config.keepalive = 5 * time.Millisecond
			s := newServer(tc.handler, func(p []byte) error { r.reports <- bytes.Clone(p); return nil }, config)
			defer s.Close()
			cid := allocate(t, s, r)
			send(t, s, cid, CommandCBOR, []byte{1})
			if got := nextCBOR(t, r, cid); !bytes.Equal(got, []byte{tc.want}) {
				t.Fatalf("response %x", got)
			}
		})
	}
}

func TestCloseJoinsAndReconnectDoesNotReuseChannels(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan struct{})
	s, r := makeServer(t, func(ctx context.Context, _ uint32, _ []byte) []byte {
		close(started)
		<-ctx.Done()
		close(finished)
		return []byte{0}
	})
	cid := allocate(t, s, r)
	send(t, s, cid, CommandCBOR, []byte{1})
	<-started
	s.Close()
	select {
	case <-finished:
	default:
		t.Fatal("Close did not join handler")
	}
	if !errors.Is(s.Handle(frame(cid, CommandPing, nil)[0]), ErrClosed) {
		t.Fatal("closed server accepted a packet")
	}
	s2, r2 := makeServer(t, nil)
	send(t, s2, cid, CommandPing, nil)
	expectError(t, r2, cid, ErrorInvalidChannel)
	for {
		select {
		case p := <-r.reports:
			if p[4] == 0x80|CommandCBOR {
				t.Fatal("Close emitted a late response")
			}
		default:
			return
		}
	}
}

func TestSenderErrorCancelsHandlerWithoutBlocking(t *testing.T) {
	started := make(chan struct{})
	ended := make(chan struct{})
	var fail atomicError
	r := &replies{reports: make(chan []byte, 1024)}
	config := defaultTiming
	config.keepalive = 2 * time.Millisecond
	s := newServer(func(ctx context.Context, _ uint32, _ []byte) []byte {
		close(started)
		<-ctx.Done()
		close(ended)
		return nil
	}, func(p []byte) error {
		if fail.get() {
			return errors.New("writer queue full")
		}
		r.reports <- bytes.Clone(p)
		return nil
	}, config)
	cid := allocate(t, s, r)
	send(t, s, cid, CommandCBOR, []byte{1})
	<-started
	fail.set()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("write failure did not cancel handler")
	}
	s.Close()
}

type atomicError struct {
	mu    sync.Mutex
	value bool
}

func (a *atomicError) get() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.value }
func (a *atomicError) set()      { a.mu.Lock(); a.value = true; a.mu.Unlock() }

func TestConcurrentCloseAndInput(t *testing.T) {
	s, r := makeServer(t, func(ctx context.Context, _ uint32, _ []byte) []byte { <-ctx.Done(); return nil })
	cid := allocate(t, s, r)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				_ = s.Handle(frame(cid, CommandCBOR, []byte{1})[0])
				_ = s.Handle(frame(cid, CommandCancel, nil)[0])
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); s.Close() }()
	wg.Wait()
}
