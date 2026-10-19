// Package ctaphid implements one independent CTAP HID transport session.
package ctaphid

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ReportSize                   = 64
	MaxMessageSize               = 7609 // 57 initialization bytes plus 128*59 continuation bytes.
	MaxChannels                  = 16
	BroadcastCID          uint32 = 0xffffffff
	CommandPing           byte   = 0x01
	CommandInit           byte   = 0x06
	CommandWink           byte   = 0x08
	CommandCBOR           byte   = 0x10
	CommandCancel         byte   = 0x11
	CommandKeepalive      byte   = 0x3b
	CommandError          byte   = 0x3f
	KeepaliveProcessing   byte   = 0x01
	KeepaliveUpNeeded     byte   = 0x02
	ErrorInvalidCommand   byte   = 0x01
	ErrorInvalidParameter byte   = 0x02
	ErrorInvalidLength    byte   = 0x03
	ErrorInvalidSequence  byte   = 0x04
	ErrorMessageTimeout   byte   = 0x05
	ErrorChannelBusy      byte   = 0x06
	ErrorInvalidChannel   byte   = 0x0b
)

var (
	ErrClosed        = errors.New("ctaphid: transport is closed")
	ErrInvalidReport = errors.New("ctaphid: report must contain exactly 64 bytes")
)

// Handler receives a complete CTAP request, including its command byte. It must
// honor ctx cancellation so Close can join it. Its result includes the CTAP
// status byte. A server permits one outstanding CBOR handler at a time.
type Handler func(context.Context, uint32, []byte) []byte

type channel struct {
	generation uint64
	lastUsed   time.Time
}

type assembly struct {
	cid          uint32
	generation   uint64
	command      byte
	length       int
	nextSequence byte
	data         []byte
	deadline     time.Time
}

type operation struct {
	cid        uint32
	generation uint64
	ctx        context.Context
	cancel     context.CancelFunc
	status     atomic.Uint32
}

type keepaliveKey struct{}

// SetKeepaliveStatus changes subsequent keepalives for the current request.
// It returns false for unsupported values or a non-CTAPHID/canceled context.
func SetKeepaliveStatus(ctx context.Context, status byte) bool {
	if status != KeepaliveProcessing && status != KeepaliveUpNeeded {
		return false
	}
	op, ok := ctx.Value(keepaliveKey{}).(*operation)
	if !ok || ctx.Err() != nil {
		return false
	}
	op.status.Store(uint32(status))
	return true
}

type timing struct {
	assembly    time.Duration
	operation   time.Duration
	keepalive   time.Duration
	maintenance time.Duration
	channelIdle time.Duration
}

var defaultTiming = timing{
	assembly:    3 * time.Second,
	operation:   120 * time.Second,
	keepalive:   100 * time.Millisecond,
	maintenance: 100 * time.Millisecond,
	channelIdle: 5 * time.Minute,
}

// Server owns channels, fragment assembly, and asynchronous ceremonies for one
// connection. Create a new Server after every USB reconnect or local-client
// reconnect; Close the old server before reusing its output destination.
type Server struct {
	mu       sync.Mutex
	txMu     sync.Mutex
	wg       sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
	handler  Handler
	send     func([]byte) error
	timing   timing
	closed   bool
	failure  error
	channels map[uint32]*channel
	pending  *assembly
	op       *operation
}

// New creates a transport. send must return promptly, for example by placing a
// copied report in a bounded nonblocking writer queue. It must not call Close
// synchronously; Close waits for outstanding sends and handlers to finish.
func New(handler Handler, send func([]byte) error) *Server {
	return newServer(handler, send, defaultTiming)
}

func newServer(handler Handler, send func([]byte) error, config timing) *Server {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{ctx: ctx, cancel: cancel, handler: handler, send: send,
		timing: config, channels: make(map[uint32]*channel)}
	s.wg.Add(1)
	go s.maintain()
	return s
}

// Handle consumes a single unnumbered 64-byte HID report. Protocol errors are
// sent as CTAPHID_ERROR and return nil. Transport/write errors are returned.
// CBOR execution is asynchronous, so the caller can continue reading CANCEL.
func (s *Server) Handle(packet []byte) error {
	if len(packet) != ReportSize {
		return ErrInvalidReport
	}
	cid := binary.BigEndian.Uint32(packet)
	s.mu.Lock()
	if s.closed {
		err := s.failure
		s.mu.Unlock()
		if err != nil {
			return err
		}
		return ErrClosed
	}
	if packet[4]&0x80 != 0 && packet[4]&0x7f == CommandInit {
		return s.handleInitLocked(cid, packet)
	}
	ch := s.channels[cid]
	if cid == 0 || cid == BroadcastCID || ch == nil {
		s.mu.Unlock()
		return s.sendError(cid, ErrorInvalidChannel)
	}
	ch.lastUsed = time.Now()
	if packet[4]&0x80 != 0 && packet[4]&0x7f == CommandCancel {
		if binary.BigEndian.Uint16(packet[5:7]) != 0 {
			s.mu.Unlock()
			return s.sendError(cid, ErrorInvalidLength)
		}
		if s.op != nil && s.op.cid == cid {
			s.op.cancel()
		}
		if s.pending != nil && s.pending.cid == cid {
			s.pending = nil
		}
		s.mu.Unlock()
		return nil // CANCEL itself never has a reply.
	}
	if s.op != nil {
		s.mu.Unlock()
		return s.sendError(cid, ErrorChannelBusy)
	}
	if packet[4]&0x80 != 0 {
		if s.pending != nil {
			code := ErrorChannelBusy
			if s.pending.cid == cid {
				code = ErrorInvalidSequence
				s.pending = nil
			}
			s.mu.Unlock()
			return s.sendError(cid, code)
		}
		command := packet[4] & 0x7f
		length := int(binary.BigEndian.Uint16(packet[5:7]))
		if length > MaxMessageSize || (command == CommandCBOR && length == 0) ||
			(command == CommandWink && length != 0) {
			s.mu.Unlock()
			return s.sendError(cid, ErrorInvalidLength)
		}
		if command != CommandPing && command != CommandWink && command != CommandCBOR {
			s.mu.Unlock()
			return s.sendError(cid, ErrorInvalidCommand)
		}
		ch.generation++
		a := &assembly{cid: cid, generation: ch.generation, command: command,
			length: length, data: make([]byte, 0, length), deadline: time.Now().Add(s.timing.assembly)}
		a.data = append(a.data, packet[7:7+min(length, 57)]...)
		if len(a.data) == length {
			return s.dispatchLocked(a)
		}
		s.pending = a
		s.mu.Unlock()
		return nil
	}
	a := s.pending
	if a == nil || a.cid != cid {
		code := ErrorInvalidSequence
		if a != nil {
			code = ErrorChannelBusy
		}
		s.mu.Unlock()
		return s.sendError(cid, code)
	}
	if !time.Now().Before(a.deadline) {
		s.pending = nil
		s.mu.Unlock()
		return s.sendError(cid, ErrorMessageTimeout)
	}
	if packet[4] != a.nextSequence {
		s.pending = nil
		s.mu.Unlock()
		return s.sendError(cid, ErrorInvalidSequence)
	}
	a.nextSequence++
	a.data = append(a.data, packet[5:5+min(a.length-len(a.data), 59)]...)
	if len(a.data) == a.length {
		s.pending = nil
		return s.dispatchLocked(a)
	}
	s.mu.Unlock()
	return nil
}

// These helpers are entered with mu held and always release it before returning.
func (s *Server) handleInitLocked(cid uint32, packet []byte) error {
	if binary.BigEndian.Uint16(packet[5:7]) != 8 {
		s.mu.Unlock()
		return s.sendError(cid, ErrorInvalidLength)
	}
	if cid == BroadcastCID {
		var err error
		cid, err = s.allocateChannelLocked()
		if err != nil {
			s.mu.Unlock()
			return s.sendError(BroadcastCID, ErrorChannelBusy)
		}
	} else if cid == 0 || s.channels[cid] == nil {
		s.mu.Unlock()
		return s.sendError(cid, ErrorInvalidChannel)
	}
	ch := s.channels[cid]
	ch.generation++
	ch.lastUsed = time.Now()
	if s.pending != nil && s.pending.cid == cid {
		s.pending = nil
	}
	if s.op != nil && s.op.cid == cid {
		s.op.cancel()
	}
	response := make([]byte, 17)
	copy(response, packet[7:15])
	binary.BigEndian.PutUint32(response[8:12], cid)
	response[12], response[13], response[14], response[15] = 2, 0, 4, 0
	response[16] = 0x0d // WINK | CBOR | NMSG; CTAP1 MSG is not implemented.
	gen := ch.generation
	wireCID := binary.BigEndian.Uint32(packet)
	s.mu.Unlock()
	return s.sendMessage(wireCID, CommandInit, response, cid, gen)
}

func (s *Server) allocateChannelLocked() (uint32, error) {
	if len(s.channels) >= MaxChannels {
		var oldest uint32
		var at time.Time
		for cid, ch := range s.channels {
			if (s.op != nil && s.op.cid == cid) || (s.pending != nil && s.pending.cid == cid) {
				continue
			}
			if oldest == 0 || ch.lastUsed.Before(at) {
				oldest, at = cid, ch.lastUsed
			}
		}
		if oldest == 0 {
			return 0, errors.New("all channels are busy")
		}
		delete(s.channels, oldest)
	}
	for i := 0; i < 128; i++ {
		var bytes [4]byte
		if _, err := rand.Read(bytes[:]); err != nil {
			return 0, err
		}
		cid := binary.BigEndian.Uint32(bytes[:])
		if cid != 0 && cid != BroadcastCID && s.channels[cid] == nil {
			s.channels[cid] = &channel{lastUsed: time.Now()}
			return cid, nil
		}
	}
	return 0, errors.New("cannot allocate a channel")
}

func (s *Server) dispatchLocked(a *assembly) error {
	if a.command != CommandCBOR {
		s.mu.Unlock()
		return s.sendMessage(a.cid, a.command, a.data, a.cid, a.generation)
	}
	ctx, cancel := context.WithTimeout(s.ctx, s.timing.operation)
	op := &operation{cid: a.cid, generation: a.generation, ctx: ctx, cancel: cancel}
	op.status.Store(uint32(KeepaliveProcessing))
	op.ctx = context.WithValue(ctx, keepaliveKey{}, op)
	s.op = op
	s.wg.Add(1)
	s.mu.Unlock()
	go s.runOperation(op, a.data)
	return nil
}

func (s *Server) runOperation(op *operation, request []byte) {
	defer s.wg.Done()
	keepaliveDone := make(chan struct{})
	go func() {
		defer close(keepaliveDone)
		ticker := time.NewTicker(s.timing.keepalive)
		defer ticker.Stop()
		for {
			select {
			case <-op.ctx.Done():
				return
			case <-ticker.C:
				if op.ctx.Err() != nil {
					return
				}
				if err := s.sendMessage(op.cid, CommandKeepalive, []byte{byte(op.status.Load())}, op.cid, op.generation); err != nil {
					return
				}
			}
		}
	}()
	response := s.callHandler(op.ctx, op.cid, request)
	err := op.ctx.Err()
	op.cancel()
	<-keepaliveDone
	if errors.Is(err, context.DeadlineExceeded) {
		response = []byte{0x2f}
	} else if err != nil {
		response = []byte{0x2d}
	}
	if len(response) == 0 || len(response) > MaxMessageSize {
		response = []byte{0x7f}
	}
	_ = s.sendMessage(op.cid, CommandCBOR, response, op.cid, op.generation)
	s.mu.Lock()
	if s.op == op {
		s.op = nil
	}
	s.mu.Unlock()
}

func (s *Server) callHandler(ctx context.Context, cid uint32, request []byte) (response []byte) {
	defer func() {
		if recover() != nil {
			response = []byte{0x7f}
		}
	}()
	if s.handler == nil {
		return []byte{0x7f}
	}
	return s.handler(ctx, cid, request)
}

func (s *Server) sendError(cid uint32, code byte) error {
	return s.sendMessage(cid, CommandError, []byte{code}, 0, 0)
}

func (s *Server) sendMessage(cid uint32, command byte, data []byte, guardCID uint32, generation uint64) error {
	if len(data) > MaxMessageSize {
		return fmt.Errorf("ctaphid: response too long: %d", len(data))
	}
	s.txMu.Lock()
	defer s.txMu.Unlock()
	position, sequence := 0, byte(0)
	for first := true; first || position < len(data); first = false {
		s.mu.Lock()
		valid := !s.closed
		if guardCID != 0 {
			ch := s.channels[guardCID]
			valid = valid && ch != nil && ch.generation == generation
		}
		s.mu.Unlock()
		if !valid {
			return nil
		}
		report := make([]byte, ReportSize)
		binary.BigEndian.PutUint32(report, cid)
		start := 5
		if first {
			report[4] = 0x80 | command
			binary.BigEndian.PutUint16(report[5:7], uint16(len(data)))
			start = 7
		} else {
			report[4] = sequence
			sequence++
		}
		n := copy(report[start:], data[position:])
		position += n
		if s.send == nil {
			s.fail(errors.New("ctaphid: missing sender"))
			return errors.New("ctaphid: missing sender")
		}
		if err := s.send(report); err != nil {
			s.fail(err)
			return err
		}
	}
	return nil
}

func (s *Server) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		s.failure = err
		s.pending = nil
		s.cancel()
		if s.op != nil {
			s.op.cancel()
		}
	}
}

func (s *Server) maintain() {
	defer s.wg.Done()
	ticker := time.NewTicker(s.timing.maintenance)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case now := <-ticker.C:
			s.expire(now)
		}
	}
}

func (s *Server) expire(now time.Time) {
	s.mu.Lock()
	var expired *assembly
	if s.pending != nil && !now.Before(s.pending.deadline) {
		expired = s.pending
		s.pending = nil
	}
	for cid, ch := range s.channels {
		if (s.op != nil && s.op.cid == cid) || (s.pending != nil && s.pending.cid == cid) {
			continue
		}
		if now.Sub(ch.lastUsed) >= s.timing.channelIdle {
			delete(s.channels, cid)
		}
	}
	s.mu.Unlock()
	if expired != nil {
		_ = s.sendMessage(expired.cid, CommandError, []byte{ErrorMessageTimeout}, expired.cid, expired.generation)
	}
}

// Close prevents new messages, cancels the in-flight handler, and joins all
// server goroutines. A blocked transport writer must be closed by its owner;
// the send callback contract intentionally requires bounded/nonblocking sends.
func (s *Server) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.pending = nil
		s.cancel()
		if s.op != nil {
			s.op.cancel()
		}
	}
	s.mu.Unlock()
	s.wg.Wait()
}
