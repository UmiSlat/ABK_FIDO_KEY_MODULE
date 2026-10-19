package control

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/UmiSlat/abk-fido-daemon/internal/authenticator"
)

// Broker never grants approval on its own. Only a root control client may
// answer the currently pending, unpredictable request ID. Cancellation removes
// that request before a subsequent ceremony can receive an answer.
type Broker struct {
	mu      sync.Mutex
	pending *Pending
	answer  chan bool
}

type Pending struct {
	ID      int    `json:"request_id"`
	Command string `json:"command"`
	RPID    string `json:"rp_id"`
	UV      bool   `json:"uv"`
	RK      bool   `json:"rk"`
}

func (b *Broker) Approve(ctx context.Context, a authenticator.Approval) error {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	id := int(binary.BigEndian.Uint32(raw[:]) & 0x7fffffff)
	if id == 0 {
		id = 1
	}
	b.mu.Lock()
	if b.pending != nil {
		b.mu.Unlock()
		return errors.New("another approval is pending")
	}
	p := &Pending{id, a.Command, a.RPID, a.UV, a.RK}
	answer := make(chan bool, 1)
	b.pending, b.answer = p, answer
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		if b.pending == p {
			b.pending, b.answer = nil, nil
		}
		b.mu.Unlock()
	}()
	timer := time.NewTimer(55 * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("local approval timed out")
	case allow := <-answer:
		if err := ctx.Err(); err != nil {
			return err
		}
		if !allow {
			return errors.New("local approval denied")
		}
		return nil
	}
}

func (b *Broker) Pending() *Pending {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		return nil
	}
	p := *b.pending
	return &p
}

func (b *Broker) Decide(id int, allow bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil || id <= 0 || b.pending.ID != id {
		return errors.New("stale approval request")
	}
	select {
	case b.answer <- allow:
		return nil
	default:
		return errors.New("request already answered")
	}
}
