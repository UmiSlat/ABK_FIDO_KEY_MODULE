package control

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/UmiSlat/abk-fido-daemon/internal/authenticator"
)

func pendingApproval(t *testing.T, b *Broker) *Pending {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if p := b.Pending(); p != nil {
			return p
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("approval did not become pending")
	return nil
}

func TestBrokerRequiresExplicitMatchingDecision(t *testing.T) {
	b := &Broker{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- b.Approve(ctx, authenticator.Approval{Command: "makeCredential", RPID: "example.com", UV: true, RK: true})
	}()
	p := pendingApproval(t, b)
	if p.ID <= 0 || p.Command != "makeCredential" || p.RPID != "example.com" || !p.UV || !p.RK {
		t.Fatalf("bad pending request: %+v", p)
	}
	select {
	case err := <-done:
		t.Fatalf("approval granted without decision: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	copy := b.Pending()
	copy.RPID = "tampered"
	if b.Pending().RPID != "example.com" {
		t.Fatal("Pending leaked mutable state")
	}
	if err := b.Decide(p.ID+1, true); err == nil {
		t.Fatal("stale ID accepted")
	}
	if err := b.Decide(p.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if b.Pending() != nil {
		t.Fatal("completed request still pending")
	}
	if err := b.Decide(p.ID, true); err == nil {
		t.Fatal("completed approval reused")
	}
}

func TestBrokerDenyCancelAndStaleDecision(t *testing.T) {
	b := &Broker{}
	for _, allow := range []bool{false, true} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- b.Approve(ctx, authenticator.Approval{Command: "getAssertion"}) }()
		p := pendingApproval(t, b)
		if allow {
			cancel()
		} else {
			if err := b.Decide(p.ID, false); err != nil {
				t.Fatal(err)
			}
		}
		err := <-done
		cancel()
		if err == nil {
			t.Fatal("denied/canceled request approved")
		}
		if allow && !errors.Is(err, context.Canceled) {
			t.Fatalf("wrong cancel error: %v", err)
		}
		if b.Pending() != nil {
			t.Fatal("canceled request still pending")
		}
		if err := b.Decide(p.ID, true); err == nil {
			t.Fatal("stale request ID accepted after cancellation")
		}
	}
}

func TestBrokerOnlyOnePendingRequest(t *testing.T) {
	b := &Broker{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.Approve(ctx, authenticator.Approval{}) }()
	pendingApproval(t, b)
	if err := b.Approve(context.Background(), authenticator.Approval{}); err == nil {
		t.Fatal("second pending approval accepted")
	}
	cancel()
	<-done
}
