// Package authenticator implements the CTAP2 authenticator independently of
// USB, Android, and the approval UI. Its store is compatible with ABK v1/v2.
package authenticator

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Approval struct {
	Command, RPID string
	UV, RK        bool
}

// Approver must return only after local biometric/screen-lock verification,
// and must honor ctx. An absent approver is never interpreted as consent.
type Approver func(context.Context, Approval) error
type Status struct {
	CredentialCount      int
	Generation           uint64
	LastError, LastTrace string
}

var (
	ErrConflict        = errors.New("store generation changed")
	ErrCounterRollback = errors.New("signature counter cannot move backwards")
)

type Engine struct {
	mu                   sync.Mutex
	gate                 chan struct{}
	store                store
	generation           uint64
	approve              Approver
	write                func([]byte) error
	writeError           error
	keyAgreement         *ecdh.PrivateKey
	next                 *assertionState
	session              string
	cid                  uint32
	lastError, lastTrace string
	now                  func() time.Time
}
type assertionState struct {
	session     string
	cid         uint32
	generation  uint64
	rp          string
	hash        []byte
	slots       []int
	includeUser bool
	hmac        *hmacRequest
	expires     time.Time
}

type ctapError byte

func (e ctapError) Error() string { return fmt.Sprintf("CTAP error 0x%02x", byte(e)) }

const (
	invalidCommand       ctapError = 0x01
	invalidParameter     ctapError = 0x02
	invalidLength        ctapError = 0x03
	channelBusy          ctapError = 0x06
	unexpectedType       ctapError = 0x11
	invalidCBOR          ctapError = 0x12
	missingParameter     ctapError = 0x14
	limitExceeded        ctapError = 0x15
	credentialExcluded   ctapError = 0x19
	unsupportedAlgorithm ctapError = 0x26
	operationDenied      ctapError = 0x27
	keyStoreFull         ctapError = 0x28
	unsupportedOption    ctapError = 0x2b
	invalidOption        ctapError = 0x2c
	keepaliveCancel      ctapError = 0x2d
	noCredentials        ctapError = 0x2e
	userActionTimeout    ctapError = 0x2f
	notAllowed           ctapError = 0x30
	pinAuthInvalid       ctapError = 0x33
	pinNotSet            ctapError = 0x35
	upRequired           ctapError = 0x3b
	otherError           ctapError = 0x7f
)

func New(storePath string, approve Approver) (*Engine, error) {
	if approve == nil {
		return nil, errors.New("local approval provider is required")
	}
	if storePath == "" || !filepath.IsAbs(storePath) {
		return nil, errors.New("an absolute store path is required")
	}
	e := &Engine{gate: make(chan struct{}, 1), approve: approve, now: time.Now}
	e.write = func(b []byte) error { return atomicWrite(storePath, b) }
	info, err := os.Lstat(storePath)
	if err == nil {
		if !info.Mode().IsRegular() {
			return nil, errors.New("store must be a regular file")
		}
		if info.Size() != storeSize && info.Size() != legacyStoreSize {
			return nil, errors.New("invalid store length")
		}
		b, readErr := os.ReadFile(storePath)
		if readErr != nil {
			return nil, readErr
		}
		e.store, err = parseStore(b)
		if err != nil {
			return nil, err
		}
		// The daemon is the only writer; also tighten an old permissive file.
		if err = os.Chmod(storePath, 0600); err != nil {
			return nil, err
		}
	} else if errors.Is(err, os.ErrNotExist) {
		e.store, err = newStore()
		if err != nil {
			return nil, err
		}
		if err = e.write(e.store.encode()); err != nil {
			return nil, err
		}
	} else {
		return nil, err
	}
	e.keyAgreement, err = ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	var seed [8]byte
	if _, err = rand.Read(seed[:]); err != nil {
		return nil, err
	}
	// A fresh process gets a fresh CAS domain, within exact JSON integer range.
	e.generation = (binary.BigEndian.Uint64(seed[:]) & ((1 << 52) - 1)) + 1
	e.lastTrace = "authenticator ready"
	return e, nil
}

func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{Generation: e.generation, LastError: e.lastError, LastTrace: e.lastTrace}
	for _, c := range e.store.Credentials {
		if c.Used {
			s.CredentialCount++
		}
	}
	return s
}
func (e *Engine) Snapshot() ([]byte, uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.store.encode(), e.generation, nil
}
func (e *Engine) Replace(blob []byte, expectedGeneration uint64) error {
	s, err := parseStore(blob)
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.generation != expectedGeneration {
		return ErrConflict
	}
	if s.Counter < e.store.Counter {
		return ErrCounterRollback
	}
	if err = e.commitLocked(s); err != nil {
		return err
	}
	e.next = nil
	e.lastError = ""
	e.lastTrace = "store replaced"
	return nil
}

// commitLocked publishes only after the temp file, rename and directory sync
// succeed. Any I/O error freezes further writes until restart: after a failed
// directory fsync, whether rename survived a power loss cannot be established.
func (e *Engine) commitLocked(s store) error {
	if e.writeError != nil {
		return fmt.Errorf("store writes blocked until restart: %w", e.writeError)
	}
	if err := e.write(s.encode()); err != nil {
		e.writeError = err
		e.lastError = "store persistence failed: " + err.Error()
		return err
	}
	e.store = s
	e.generation++
	return nil
}

func contextStatus(ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return userActionTimeout
	}
	if ctx.Err() != nil {
		return keepaliveCancel
	}
	return nil
}

// Execute consumes a CTAP command byte followed by its CBOR parameters and
// returns a CTAP status byte followed by canonical response CBOR. A session
// must identify one transport connection/epoch, not just a reusable device.
func (e *Engine) Execute(ctx context.Context, session string, cid uint32, payload []byte) []byte {
	if ctx == nil {
		ctx = context.Background()
	}
	if len(payload) == 0 {
		return []byte{byte(invalidLength)}
	}
	if len(payload) > maxMessage {
		return []byte{byte(limitExceeded)}
	}
	if session == "" || cid == 0 || cid == math.MaxUint32 {
		return []byte{byte(invalidParameter)}
	}
	select {
	case e.gate <- struct{}{}:
		defer func() { <-e.gate }()
	default:
		return []byte{byte(channelBusy)}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.session != session || e.cid != cid {
		e.next = nil
		e.session = session
		e.cid = cid
	}
	cmd := payload[0]
	if cmd != 0x02 && cmd != 0x08 {
		e.next = nil
	}
	var req object
	if len(payload) > 1 {
		v, err := decodeCBOR(payload[1:])
		if err != nil {
			return e.failure(invalidCBOR)
		}
		var ok bool
		req, ok = v.(object)
		if !ok {
			return e.failure(unexpectedType)
		}
	}
	if err := contextStatus(ctx); err != nil {
		return e.failure(err)
	}
	var response any
	var err error
	switch cmd {
	case 0x04:
		if len(payload) != 1 {
			return e.failure(invalidCBOR)
		}
		response = object{1: []any{"FIDO_2_0"}, 2: []any{"hmac-secret"}, 3: e.store.AAGUID[:], 4: object{"rk": true, "up": true, "uv": true, "plat": false}, 5: maxMessage, 6: []any{1}, 7: 16, 8: 32}
	case 0x01:
		response, err = e.makeCredential(ctx, session, cid, req)
	case 0x02:
		response, err = e.getAssertion(ctx, session, cid, req)
	case 0x08:
		if len(payload) != 1 {
			return e.failure(invalidCBOR)
		}
		response, err = e.nextAssertion(ctx, session, cid)
	case 0x06:
		response, err = e.clientPIN(req)
	case 0x07:
		if len(payload) != 1 {
			return e.failure(invalidCBOR)
		}
		err = e.approvalLocked(ctx, Approval{Command: "reset", UV: true})
		if err == nil {
			var s store
			var key *ecdh.PrivateKey
			s, err = newStore()
			if err == nil {
				key, err = ecdh.P256().GenerateKey(rand.Reader)
			}
			if err == nil {
				err = e.commitLocked(s)
			}
			if err == nil {
				e.keyAgreement = key
				e.next = nil
				e.lastTrace = "authenticator reset"
			}
		}
	case 0x0b:
		if len(payload) != 1 {
			return e.failure(invalidCBOR)
		}
		err = e.approvalLocked(ctx, Approval{Command: "selection", UV: true})
		if err == nil {
			e.lastTrace = "selection approved"
		}
	default:
		err = invalidCommand
	}
	if err != nil {
		return e.failure(err)
	}
	if err = contextStatus(ctx); err != nil {
		e.next = nil
		return e.failure(err)
	}
	e.lastError = ""
	if response == nil {
		return []byte{0}
	}
	return append([]byte{0}, encodeCBOR(response)...)
}
func (e *Engine) failure(err error) []byte {
	e.next = nil
	e.lastError = err.Error()
	var status ctapError
	if !errors.As(err, &status) {
		status = otherError
	}
	return []byte{byte(status)}
}
func (e *Engine) approvalLocked(ctx context.Context, a Approval) error {
	if err := contextStatus(ctx); err != nil {
		return err
	}
	generation := e.generation
	e.lastTrace = a.Command + " awaiting local approval rp=" + a.RPID
	e.mu.Unlock()
	err := e.approve(ctx, a)
	e.mu.Lock()
	if cancelled := contextStatus(ctx); cancelled != nil {
		return cancelled
	}
	if err != nil {
		return operationDenied
	}
	if generation != e.generation {
		return notAllowed
	}
	return nil
}

func value(m object, key any) (any, bool) {
	if n, ok := key.(int); ok {
		key = int64(n)
	}
	v, ok := m[key]
	return v, ok
}
func mapValue(m object, key any, required bool) (object, error) {
	v, ok := value(m, key)
	if !ok {
		if required {
			return nil, missingParameter
		}
		return nil, nil
	}
	o, ok := v.(object)
	if !ok {
		return nil, unexpectedType
	}
	return o, nil
}
func bytesValue(m object, key any, min, max int, required bool) ([]byte, error) {
	v, ok := value(m, key)
	if !ok {
		if required {
			return nil, missingParameter
		}
		return nil, nil
	}
	b, ok := v.([]byte)
	if !ok {
		return nil, unexpectedType
	}
	if len(b) < min || len(b) > max {
		return nil, invalidParameter
	}
	return b, nil
}
func textValue(m object, key any, max int, required bool) (string, error) {
	v, ok := value(m, key)
	if !ok {
		if required {
			return "", missingParameter
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", unexpectedType
	}
	if len(s) > max || strings.ContainsRune(s, 0) {
		return "", invalidParameter
	}
	return s, nil
}
func boolValue(m object, key any, def bool) (bool, error) {
	v, ok := value(m, key)
	if !ok {
		return def, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, unexpectedType
	}
	return b, nil
}
func intValue(m object, key any, required bool) (int64, error) {
	v, ok := value(m, key)
	if !ok {
		if required {
			return 0, missingParameter
		}
		return 0, nil
	}
	n, ok := v.(int64)
	if !ok {
		return 0, unexpectedType
	}
	return n, nil
}
func descriptorIDs(m object, key any) ([][]byte, error) {
	v, ok := value(m, key)
	if !ok {
		return nil, nil
	}
	a, ok := v.([]any)
	if !ok {
		return nil, unexpectedType
	}
	if len(a) > 64 {
		return nil, limitExceeded
	}
	var ids [][]byte
	for _, v := range a {
		d, ok := v.(object)
		if !ok {
			return nil, unexpectedType
		}
		t, err := textValue(d, "type", 64, true)
		if err != nil {
			return nil, err
		}
		id, err := bytesValue(d, "id", 1, 1023, true)
		if err != nil {
			return nil, err
		}
		if t == "public-key" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

func (e *Engine) makeCredential(ctx context.Context, session string, cid uint32, req object) (any, error) {
	hash, err := bytesValue(req, 1, 32, 32, true)
	if err != nil {
		return nil, err
	}
	rp, err := mapValue(req, 2, true)
	if err != nil {
		return nil, err
	}
	rpid, err := textValue(rp, "id", 127, true)
	if err != nil {
		return nil, err
	}
	if rpid == "" {
		return nil, invalidParameter
	}
	user, err := mapValue(req, 3, true)
	if err != nil {
		return nil, err
	}
	uid, err := bytesValue(user, "id", 1, 64, true)
	if err != nil {
		return nil, err
	}
	name, err := textValue(user, "name", 1024, false)
	if err != nil {
		return nil, err
	}
	display, err := textValue(user, "displayName", 1024, false)
	if err != nil {
		return nil, err
	}
	name = storeName(name)
	display = storeName(display)
	params, present := value(req, 4)
	if !present {
		return nil, missingParameter
	}
	algs, ok := params.([]any)
	if !ok {
		return nil, unexpectedType
	}
	supported := false
	for _, p := range algs {
		a, ok := p.(object)
		if !ok {
			return nil, unexpectedType
		}
		alg, err := intValue(a, "alg", true)
		if err != nil {
			return nil, err
		}
		typ, err := textValue(a, "type", 64, true)
		if err != nil {
			return nil, err
		}
		if alg == -7 && typ == "public-key" {
			supported = true
		}
	}
	if !supported {
		return nil, unsupportedAlgorithm
	}
	exclude, err := descriptorIDs(req, 5)
	if err != nil {
		return nil, err
	}
	opts, err := mapValue(req, 7, false)
	if err != nil {
		return nil, err
	}
	rk, err := boolValue(opts, "rk", false)
	if err != nil {
		return nil, err
	}
	uv, err := boolValue(opts, "uv", false)
	if err != nil {
		return nil, err
	}
	up, err := boolValue(opts, "up", true)
	if err != nil {
		return nil, err
	}
	if !up {
		return nil, invalidOption
	}
	if _, present := value(req, 8); present {
		return nil, pinNotSet
	}
	ext, err := mapValue(req, 6, false)
	if err != nil {
		return nil, err
	}
	hmacEnabled, err := boolValue(ext, "hmac-secret", false)
	if err != nil {
		return nil, err
	}
	selection := (rpid == "SelectDevice" && name == "SelectDevice") || (rpid == ".dummy" && name == "dummy")
	command := "makeCredential"
	if selection {
		command = "selection"
	}
	if err = e.approvalLocked(ctx, Approval{Command: command, RPID: rpid, UV: true, RK: rk}); err != nil {
		return nil, err
	}
	_ = uv
	if !selection {
		for _, c := range e.store.Credentials {
			if c.Used && c.RPID == rpid {
				for _, id := range exclude {
					if bytes.Equal(c.ID[:], id) {
						return nil, credentialExcluded
					}
				}
			}
		}
	}
	slot := -1
	if rk {
		// CTAP discoverable credentials are unique per RP and user handle.
		// Re-registration replaces that account even when the store is full;
		// excludeList was already checked after fresh local approval above.
		for i, c := range e.store.Credentials {
			if c.Used && c.Resident && c.RPID == rpid && bytes.Equal(c.UserID, uid) {
				slot = i
				break
			}
		}
	}
	if slot < 0 {
		for i, c := range e.store.Credentials {
			if !c.Used {
				slot = i
				break
			}
		}
	}
	if !selection && slot < 0 {
		return nil, keyStoreFull
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	c := credential{Used: true, Resident: rk, RPID: rpid, UserID: bytes.Clone(uid), Name: name, Display: display}
	key.D.FillBytes(c.Private[:])
	key.X.FillBytes(c.Public[:32])
	key.Y.FillBytes(c.Public[32:])
	for {
		if _, err = rand.Read(c.ID[:]); err != nil {
			return nil, err
		}
		duplicate := false
		for _, old := range e.store.Credentials {
			if old.Used && old.ID == c.ID {
				duplicate = true
				break
			}
		}
		if !duplicate {
			break
		}
	}
	if hmacEnabled {
		if _, err = rand.Read(c.HMACSecret[:]); err != nil {
			return nil, err
		}
	}
	var extensions object
	if hmacEnabled {
		extensions = object{"hmac-secret": true}
	}
	ad := attestedAuthData(&e.store, &c, extensions)
	sig, err := sign(&c, ad, hash)
	if err != nil {
		return nil, err
	}
	response := object{1: "packed", 2: ad, 3: object{"alg": -7, "sig": sig}}
	if err = contextStatus(ctx); err != nil {
		return nil, err
	}
	if !selection {
		s := e.store
		if rk {
			// Old kernel stores can already contain several discoverable
			// credentials for this account. Retire all of them atomically
			// with replacement, while leaving imports alone until approval.
			for i, old := range s.Credentials {
				if old.Used && old.Resident && old.RPID == rpid && bytes.Equal(old.UserID, uid) {
					s.Credentials[i] = credential{}
				}
			}
		}
		s.Credentials[slot] = c
		if err = e.commitLocked(s); err != nil {
			return nil, err
		}
	}
	e.lastTrace = command + " complete rp=" + rpid
	return response, nil
}

func (e *Engine) getAssertion(ctx context.Context, session string, cid uint32, req object) (any, error) {
	e.next = nil
	rp, err := textValue(req, 1, 127, true)
	if err != nil {
		return nil, err
	}
	if rp == "" {
		return nil, invalidParameter
	}
	hash, err := bytesValue(req, 2, 32, 32, true)
	if err != nil {
		return nil, err
	}
	allow, err := descriptorIDs(req, 3)
	if err != nil {
		return nil, err
	}
	_, allowPresent := value(req, 3)
	if raw, present := value(req, 3); present && len(raw.([]any)) == 0 {
		allowPresent = false
	}
	opts, err := mapValue(req, 5, false)
	if err != nil {
		return nil, err
	}
	uv, err := boolValue(opts, "uv", false)
	if err != nil {
		return nil, err
	}
	_ = uv
	up, err := boolValue(opts, "up", true)
	if err != nil {
		return nil, err
	}
	if _, present := value(req, 6); present {
		return nil, pinNotSet
	}
	ext, err := mapValue(req, 4, false)
	if err != nil {
		return nil, err
	}
	hm, err := e.parseHMAC(ext)
	if err != nil {
		return nil, err
	}
	if !up && hm != nil {
		return nil, unsupportedOption
	}
	if !up {
		return nil, upRequired
	}
	var slots []int
	for i, c := range e.store.Credentials {
		if !c.Used || c.RPID != rp {
			continue
		}
		match := !allowPresent && c.Resident
		for _, id := range allow {
			if bytes.Equal(id, c.ID[:]) {
				match = true
				break
			}
		}
		if match {
			slots = append(slots, i)
			if allowPresent {
				break
			}
		}
	}
	if err = e.approvalLocked(ctx, Approval{Command: "getAssertion", RPID: rp, UV: true}); err != nil {
		return nil, err
	}
	// An unverified caller must not distinguish a known RP/credential from an
	// unknown one by observing whether the phone asks for consent.
	if len(slots) == 0 {
		return nil, noCredentials
	}
	a := &assertionState{session: session, cid: cid, rp: rp, hash: bytes.Clone(hash), slots: slots, includeUser: !allowPresent, hmac: hm, expires: e.now().Add(30 * time.Second)}
	response, err := e.assertionLocked(ctx, a, slots[0], len(slots))
	if err != nil {
		return nil, err
	}
	if len(slots) > 1 {
		a.slots = slots[1:]
		a.generation = e.generation
		e.next = a
	}
	return response, nil
}
func (e *Engine) nextAssertion(ctx context.Context, session string, cid uint32) (any, error) {
	a := e.next
	if a == nil || a.session != session || a.cid != cid || a.generation != e.generation || !e.now().Before(a.expires) {
		e.next = nil
		return nil, notAllowed
	}
	if len(a.slots) == 0 {
		e.next = nil
		return nil, notAllowed
	}
	response, err := e.assertionLocked(ctx, a, a.slots[0], 0)
	if err != nil {
		e.next = nil
		return nil, err
	}
	a.slots = a.slots[1:]
	a.generation = e.generation
	if len(a.slots) == 0 {
		e.next = nil
	}
	return response, nil
}
func (e *Engine) assertionLocked(ctx context.Context, a *assertionState, slot, total int) (any, error) {
	if e.store.Counter == math.MaxUint32 {
		return nil, limitExceeded
	}
	c := &e.store.Credentials[slot]
	if !c.Used || c.RPID != a.rp {
		return nil, notAllowed
	}
	var ext object
	if a.hmac != nil && !allZero(c.HMACSecret[:]) {
		output, err := a.hmac.output(c.HMACSecret[:])
		if err != nil {
			return nil, err
		}
		ext = object{"hmac-secret": output}
	}
	count := e.store.Counter + 1
	ad := authData(a.rp, count, 5, ext)
	sig, err := sign(c, ad, a.hash)
	if err != nil {
		return nil, err
	}
	response := object{1: object{"id": c.ID[:], "type": "public-key"}, 2: ad, 3: sig}
	if a.includeUser {
		user := object{"id": c.UserID}
		if c.Name != "" {
			user["name"] = c.Name
		}
		if c.Display != "" {
			user["displayName"] = c.Display
		}
		response[4] = user
	}
	if total > 1 {
		response[5] = total
	}
	if err = contextStatus(ctx); err != nil {
		return nil, err
	}
	s := e.store
	s.Counter = count
	if err = e.commitLocked(s); err != nil {
		return nil, err
	}
	e.lastTrace = "getAssertion complete rp=" + a.rp
	return response, nil
}

func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}

func storeName(s string) string {
	for len(s) > 63 {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	return s
}
func coseKey(public []byte, alg int64) object {
	return object{1: 2, 3: alg, -1: 1, -2: public[:32], -3: public[32:]}
}
func authData(rp string, count uint32, flags byte, ext object) []byte {
	h := sha256.Sum256([]byte(rp))
	b := append([]byte(nil), h[:]...)
	if len(ext) > 0 {
		flags |= 0x80
	}
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, count)
	if len(ext) > 0 {
		b = append(b, encodeCBOR(ext)...)
	}
	return b
}
func attestedAuthData(s *store, c *credential, ext object) []byte {
	b := authData(c.RPID, s.Counter, 0x45, nil)
	if len(ext) > 0 {
		b[32] |= 0x80
	}
	b = append(b, s.AAGUID[:]...)
	b = binary.BigEndian.AppendUint16(b, 32)
	b = append(b, c.ID[:]...)
	b = append(b, encodeCBOR(coseKey(c.Public[:], -7))...)
	if len(ext) > 0 {
		b = append(b, encodeCBOR(ext)...)
	}
	return b
}
func sign(c *credential, ad, clientHash []byte) ([]byte, error) {
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write(ad)
	h.Write(clientHash)
	return ecdsa.SignASN1(rand.Reader, key, h.Sum(nil))
}
