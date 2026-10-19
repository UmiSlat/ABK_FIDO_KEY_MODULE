package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/UmiSlat/abk-fido-daemon/internal/authenticator"
	"github.com/UmiSlat/abk-fido-daemon/internal/ctaphid"
)

func testControl(t *testing.T) *Server {
	t.Helper()
	b := &Broker{}
	engine, err := authenticator.New(filepath.Join(t.TempDir(), "store.bin"), b.Approve)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(engine, b)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func testSocket(t *testing.T, s *Server) (string, context.CancelFunc) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, path) }()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Lstat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("socket not created")
		}
		time.Sleep(time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("socket server did not shut down")
		}
	})
	return path, cancel
}

func rawCall(t *testing.T, path string, raw []byte) Response {
	t.Helper()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err = c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	var resp Response
	if err = json.NewDecoder(c).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUnixSocketPeerCredentialsAndBounds(t *testing.T) {
	s := testControl(t)
	path, _ := testSocket(t, s)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("socket permissions: %v %v", info, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	data, err := Call(ctx, path, Request{Op: "status"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"backend":"userspace"`)) {
		t.Fatalf("wrong status: %s", data)
	}
	for _, raw := range [][]byte{[]byte(`{"op":"status","extra":1}`), []byte(`{"op":"status"} {"op":"status"}`), []byte(`{"op":"status"}junk`), bytes.Repeat([]byte{' '}, MaxRequest+1)} {
		if r := rawCall(t, path, raw); r.OK {
			t.Fatalf("invalid request accepted, length%d", len(raw))
		}
	}
	denied := testControl(t)
	denied.AllowedUID = uint32(os.Geteuid()) + 1
	deniedPath, _ := testSocket(t, denied)
	if _, err = Call(ctx, deniedPath, Request{Op: "status"}); err == nil {
		t.Fatal("nonmatching peer UID accepted")
	}
}

func TestUnixSocketContextCancellationClosesIdleClients(t *testing.T) {
	s := testControl(t)
	path, cancel := testSocket(t, s)
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err = c.Write([]byte(`{"op":`)); err != nil {
		t.Fatal(err)
	}
	cancel()
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err = io.ReadAll(c)
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			t.Fatal("shutdown kept an incomplete request alive")
		}
	}
}

func TestSnapshotEpochAndGenerationCAS(t *testing.T) {
	s := testControl(t)
	ctx := context.Background()
	v, err := s.Dispatch(ctx, Request{Op: "store-get"})
	if err != nil {
		t.Fatal(err)
	}
	snap := v.(map[string]any)
	req := Request{Op: "store-put", Data: snap["blob"].(string), Epoch: snap["epoch"].(string), Generation: snap["generation"].(uint64)}
	bad := req
	bad.Epoch = "another-process"
	if _, err = s.Dispatch(ctx, bad); err == nil {
		t.Fatal("wrong epoch accepted")
	}
	bad = req
	bad.Generation++
	if _, err = s.Dispatch(ctx, bad); err == nil {
		t.Fatal("stale generation accepted")
	}
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Dispatch(ctx, req); results <- err }()
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("CAS had%d winners", wins)
	}
	if _, err = s.Dispatch(ctx, req); err == nil {
		t.Fatal("snapshot replay accepted")
	}
	other, err := New(s.Engine, s.Broker)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	fresh, _ := s.Dispatch(ctx, Request{Op: "store-get"})
	ss := fresh.(map[string]any)
	if _, err = other.Dispatch(ctx, Request{Op: "store-put", Data: ss["blob"].(string), Epoch: ss["epoch"].(string), Generation: ss["generation"].(uint64)}); err == nil {
		t.Fatal("cross-daemon snapshot accepted")
	}
}

func hidPacket(cid uint32, cmd byte, payload []byte) []byte {
	p := make([]byte, 64)
	binary.BigEndian.PutUint32(p, cid)
	p[4] = cmd | 0x80
	binary.BigEndian.PutUint16(p[5:7], uint16(len(payload)))
	copy(p[7:], payload)
	return p
}
func hidWrite(t *testing.T, s *Server, id string, p []byte) {
	t.Helper()
	if _, err := s.Dispatch(context.Background(), Request{Op: "hid-write", Session: id, Data: base64.StdEncoding.EncodeToString(p)}); err != nil {
		t.Fatal(err)
	}
}
func hidRead(t *testing.T, s *Server, id string) []byte {
	t.Helper()
	v, err := s.Dispatch(context.Background(), Request{Op: "hid-read", Session: id, TimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	p, err := base64.StdEncoding.DecodeString(v.(map[string]string)["packet"])
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func hidAllocate(t *testing.T, s *Server, id string) uint32 {
	t.Helper()
	hidWrite(t, s, id, hidPacket(ctaphid.BroadcastCID, ctaphid.CommandInit, []byte{1, 2, 3, 4, 5, 6, 7, 8}))
	return binary.BigEndian.Uint32(hidRead(t, s, id)[15:19])
}

func TestLocalSessionCIDIsolationCloseAndLimit(t *testing.T) {
	s := testControl(t)
	first := fmt.Sprintf("%032x", 1)
	second := fmt.Sprintf("%032x", 2)
	cid := hidAllocate(t, s, first)
	hidWrite(t, s, second, hidPacket(cid, ctaphid.CommandPing, nil))
	p := hidRead(t, s, second)
	if p[4] != 0x80|ctaphid.CommandError || p[7] != ctaphid.ErrorInvalidChannel {
		t.Fatal("CID crossed sessions")
	}
	s.mu.Lock()
	old := s.sessions[first]
	s.mu.Unlock()
	if _, err := s.Dispatch(context.Background(), Request{Op: "hid-close", Session: first}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.closed:
	default:
		t.Fatal("hid-close left session alive")
	}
	hidWrite(t, s, first, hidPacket(cid, ctaphid.CommandPing, nil))
	p = hidRead(t, s, first)
	if p[7] != ctaphid.ErrorInvalidChannel {
		t.Fatal("closed CID resumed")
	}
	for i := 3; i <= 16; i++ {
		hidAllocate(t, s, fmt.Sprintf("%032x", i))
	}
	if _, err := s.Dispatch(context.Background(), Request{Op: "hid-read", Session: fmt.Sprintf("%032x", 17), TimeoutMS: 1}); err == nil {
		t.Fatal("session limit exceeded")
	}
	s.Close()
	if _, err := s.Dispatch(context.Background(), Request{Op: "hid-write", Session: first, Data: base64.StdEncoding.EncodeToString(hidPacket(cid, ctaphid.CommandPing, nil))}); err == nil {
		t.Fatal("Server.Close allowed new session")
	}
}

func TestExpiredExistingSessionDoesNotResumeCID(t *testing.T) {
	s := testControl(t)
	id := fmt.Sprintf("%032x", 1)
	cid := hidAllocate(t, s, id)
	s.mu.Lock()
	old := s.sessions[id]
	old.touched = time.Now().Add(-3 * time.Minute)
	s.mu.Unlock()
	hidWrite(t, s, id, hidPacket(cid, ctaphid.CommandPing, nil))
	p := hidRead(t, s, id)
	if p[4] != 0x80|ctaphid.CommandError || p[7] != ctaphid.ErrorInvalidChannel {
		t.Fatal("expired session resumed old CID")
	}
	select {
	case <-old.closed:
	default:
		t.Fatal("expired session not canceled")
	}
}

// A host completes its last write before starting to read a synchronous PING
// response. The local transport must buffer all 129 legal response packets.
func TestLocalHIDMaximumMessageWithoutConcurrentReader(t *testing.T) {
	s := testControl(t)
	id := fmt.Sprintf("%032x", 1)
	cid := hidAllocate(t, s, id)
	payload := make([]byte, ctaphid.MaxMessageSize)
	for i := range payload {
		payload[i] = byte(i)
	}
	hidWrite(t, s, id, hidPacket(cid, ctaphid.CommandPing, payload))
	for offset, seq := 57, byte(0); offset < len(payload); offset, seq = offset+59, seq+1 {
		packet := make([]byte, 64)
		binary.BigEndian.PutUint32(packet, cid)
		packet[4] = seq
		copy(packet[5:], payload[offset:])
		hidWrite(t, s, id, packet)
	}
	first := hidRead(t, s, id)
	if first[4] != 0x80|ctaphid.CommandPing || int(binary.BigEndian.Uint16(first[5:7])) != len(payload) {
		t.Fatalf("invalid PING response header: %x", first[:7])
	}
	got := append([]byte(nil), first[7:]...)
	for seq := byte(0); len(got) < len(payload); seq++ {
		packet := hidRead(t, s, id)
		if packet[4] != seq {
			t.Fatalf("wrong response sequence: got %d, want %d", packet[4], seq)
		}
		got = append(got, packet[5:]...)
	}
	if !bytes.Equal(got[:len(payload)], payload) {
		t.Fatal("maximum PING did not round-trip")
	}
}

func TestClosingLocalSessionCancelsPendingApproval(t *testing.T) {
	s := testControl(t)
	id := fmt.Sprintf("%032x", 1)
	cid := hidAllocate(t, s, id)
	// Valid makeCredential: fresh client hash, example.com, one user, ES256.
	suffix, err := hex.DecodeString("02a16269646b6578616d706c652e636f6d03a26269644101646e616d6565616c6963650481a263616c672664747970656a7075626c69632d6b6579")
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{1, 0xa4, 1, 0x58, 0x20}, make([]byte, 32)...)
	payload = append(payload, suffix...)
	// Serialize the two-fragment HID request without depending on ctaphid internals.
	first := hidPacket(cid, ctaphid.CommandCBOR, payload)
	hidWrite(t, s, id, first)
	continuation := make([]byte, 64)
	binary.BigEndian.PutUint32(continuation, cid)
	copy(continuation[5:], payload[57:])
	hidWrite(t, s, id, continuation)
	pendingApproval(t, s.Broker)
	if _, err = s.Dispatch(context.Background(), Request{Op: "hid-close", Session: id}); err != nil {
		t.Fatal(err)
	}
	if s.Broker.Pending() != nil {
		t.Fatal("session close kept approval alive")
	}
	if s.Engine.Status().CredentialCount != 0 {
		t.Fatal("unapproved credential persisted")
	}
}

func TestUSBFailedOpenAndCanceledAttach(t *testing.T) {
	s := testControl(t)
	u := &USB{Control: s}
	defer u.Close()
	u.Attach(context.Background(), filepath.Join(t.TempDir(), "missing-hid"))
	deadline := time.Now().Add(time.Second)
	for {
		v, _ := s.Dispatch(context.Background(), Request{Op: "status"})
		m := v.(map[string]any)
		if m["usb_error"] != "" {
			if m["bound"].(bool) {
				t.Fatal("failed USB open still bound")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("missing USB open error")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	u.Attach(ctx, "/ignored")
	v, _ := s.Dispatch(context.Background(), Request{Op: "status"})
	if v.(map[string]any)["bound"].(bool) {
		t.Fatal("canceled Attach bound a USB session")
	}
}
