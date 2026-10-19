package authenticator

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testEngine(t *testing.T) (*Engine, *atomic.Int32, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "store.bin")
	calls := new(atomic.Int32)
	e, err := New(path, func(ctx context.Context, a Approval) error {
		calls.Add(1)
		if !a.UV {
			t.Error("approval must request actual verification")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, calls, path
}
func command(e *Engine, ctx context.Context, session string, cid uint32, cmd byte, m object) []byte {
	p := []byte{cmd}
	if m != nil {
		p = append(p, encodeCBOR(m)...)
	}
	return e.Execute(ctx, session, cid, p)
}
func response(t *testing.T, b []byte) object {
	t.Helper()
	if len(b) == 0 || b[0] != 0 {
		t.Fatalf("CTAP response %x", b)
	}
	v, err := decodeCBOR(b[1:])
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(object)
	if !ok {
		t.Fatal("not a response map")
	}
	return m
}
func field(m object, n int) any { return m[int64(n)] }
func makeRequest(rp, name string, hm bool) object {
	r := object{1: bytes.Repeat([]byte{0x5a}, 32), 2: object{"id": rp, "name": rp}, 3: object{"id": []byte(name), "name": name, "displayName": name}, 4: []any{object{"type": "public-key", "alg": -7}}, 7: object{"rk": true, "uv": true}}
	if hm {
		r[6] = object{"hmac-secret": true}
	}
	return r
}
func assertionRequest(rp string) object {
	return object{1: rp, 2: bytes.Repeat([]byte{0x7a}, 32), 5: object{"uv": true}}
}

// Independent authData section consumption: these tests do not simply inspect
// flag constants; both DER signatures and the complete CBOR suffix are parsed.
func inspectAuthData(t *testing.T, ad []byte) (*ecdsa.PublicKey, []byte, object) {
	t.Helper()
	if len(ad) < 37 {
		t.Fatal("short authData")
	}
	p := 37
	var pub *ecdsa.PublicKey
	var id []byte
	if ad[32]&0x40 != 0 {
		if len(ad) < 55 {
			t.Fatal("short attested data")
		}
		n := int(binary.BigEndian.Uint16(ad[53:55]))
		if 55+n > len(ad) {
			t.Fatal("short credential ID")
		}
		id = bytes.Clone(ad[55 : 55+n])
		p = 55 + n
		r := cborReader{b: ad, p: p}
		v, err := r.value(0)
		if err != nil {
			t.Fatal(err)
		}
		p = r.p
		m := v.(object)
		if field(m, 1) != int64(2) || field(m, 3) != int64(-7) || m[int64(-1)] != int64(1) {
			t.Fatal("wrong COSE key")
		}
		x, y := m[int64(-2)].([]byte), m[int64(-3)].([]byte)
		if len(x) != 32 || len(y) != 32 {
			t.Fatal("wrong point size")
		}
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			t.Fatal("invalid point")
		}
	}
	var ext object
	if ad[32]&0x80 != 0 {
		v, err := decodeCBOR(ad[p:])
		if err != nil {
			t.Fatal(err)
		}
		ext = v.(object)
		p = len(ad)
	}
	if p != len(ad) {
		t.Fatal("ED flag absent with trailing data")
	}
	return pub, id, ext
}
func verify(t *testing.T, pub *ecdsa.PublicKey, ad, clientHash, sig []byte) {
	t.Helper()
	h := sha256.New()
	h.Write(ad)
	h.Write(clientHash)
	if !ecdsa.VerifyASN1(pub, h.Sum(nil), sig) {
		t.Fatal("signature does not verify")
	}
}

func TestMakeAssertionPersistenceAndFlags(t *testing.T) {
	for _, hm := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "hmac"}[hm], func(t *testing.T) {
			e, calls, path := testEngine(t)
			req := makeRequest("openai.com", "fixture", hm)
			m := response(t, command(e, context.Background(), "usb#1", 7, 1, req))
			ad := field(m, 2).([]byte)
			pub, id, ext := inspectAuthData(t, ad)
			wantFlag := byte(0x45)
			if hm {
				wantFlag = 0xc5
			}
			if ad[32] != wantFlag {
				t.Fatalf("flags=%x", ad[32])
			}
			if hm && ext["hmac-secret"] != true {
				t.Fatal("hmac registration output")
			}
			rpHash := sha256.Sum256([]byte("openai.com"))
			if !bytes.Equal(ad[:32], rpHash[:]) {
				t.Fatal("RP hash")
			}
			if field(m, 1) != "packed" {
				t.Fatal("attestation format")
			}
			att := field(m, 3).(object)
			if att["alg"] != int64(-7) {
				t.Fatal("algorithm")
			}
			verify(t, pub, ad, req[1].([]byte), att["sig"].([]byte))
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if st.Mode().Perm() != 0600 {
				t.Fatal("store permissions")
			}
			reopened, err := New(path, func(context.Context, Approval) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			ar := assertionRequest("openai.com")
			ar[3] = []any{object{"id": id, "type": "public-key"}}
			a := response(t, command(reopened, context.Background(), "usb#2", 9, 2, ar))
			assertAD := field(a, 2).([]byte)
			_, _, extensions := inspectAuthData(t, assertAD)
			if assertAD[32] != 5 || extensions != nil || binary.BigEndian.Uint32(assertAD[33:]) != 1 {
				t.Fatal("assertion header")
			}
			verify(t, pub, assertAD, ar[2].([]byte), field(a, 3).([]byte))
			if calls.Load() != 1 {
				t.Fatal("registration approval not called")
			}
			disk, _ := os.ReadFile(path)
			s, err := parseStore(disk)
			if err != nil || s.Counter != 1 || !bytes.Equal(s.Credentials[0].ID[:], id) {
				t.Fatal("durable assertion state")
			}
		})
	}
}

func TestMandatoryApprovalExclusionAndNoCachedGrant(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "s"), nil); err == nil {
		t.Fatal("nil approver accepted")
	}
	e, calls, _ := testEngine(t)
	req := makeRequest("example.test", "one", false)
	m := response(t, command(e, context.Background(), "a", 1, 1, req))
	_, id, _ := inspectAuthData(t, field(m, 2).([]byte))
	req[5] = []any{object{"id": id, "type": "public-key"}}
	if got := command(e, context.Background(), "a", 1, 1, req); !bytes.Equal(got, []byte{0x19}) {
		t.Fatalf("exclude %x", got)
	}
	req[2] = object{"id": "other.test"}
	response(t, command(e, context.Background(), "a", 1, 1, req))
	if got := command(e, context.Background(), "a", 1, 0x0b, nil); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("selection %x", got)
	}
	req = makeRequest("third.test", "three", false)
	response(t, command(e, context.Background(), "a", 1, 1, req))
	if calls.Load() != 5 {
		t.Fatalf("operations reused approval: %d", calls.Load())
	}
	e.approve = func(context.Context, Approval) error { return errors.New("denied") }
	before := e.Status()
	if got := command(e, context.Background(), "a", 1, 7, nil); !bytes.Equal(got, []byte{0x27}) {
		t.Fatalf("reset deny %x", got)
	}
	if e.Status().Generation != before.Generation {
		t.Fatal("denied reset changed store")
	}
}

func TestSelectionDummyIsValidAndNotStored(t *testing.T) {
	e, calls, _ := testEngine(t)
	before := e.Status()
	req := makeRequest("SelectDevice", "SelectDevice", false)
	m := response(t, command(e, context.Background(), "usb", 1, 1, req))
	ad := field(m, 2).([]byte)
	pub, _, _ := inspectAuthData(t, ad)
	verify(t, pub, ad, req[1].([]byte), field(m, 3).(object)["sig"].([]byte))
	if e.Status().CredentialCount != 0 || e.Status().Generation != before.Generation || calls.Load() != 1 {
		t.Fatal("selection created a persisted credential")
	}
}

func TestContinuationSessionCIDExpiryAndReplace(t *testing.T) {
	e, calls, _ := testEngine(t)
	for _, name := range []string{"one", "two", "three"} {
		response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", name, false)))
	}
	request := assertionRequest("example.test")
	request[3] = []any{} // Empty and omitted allowList both discover resident keys.
	a := response(t, command(e, context.Background(), "a", 1, 2, request))
	if field(a, 5) != int64(3) {
		t.Fatal("missing credential count")
	}
	if field(a, 4).(object)["id"] == nil {
		t.Fatal("discoverable account handle missing")
	}
	seen := map[string]bool{string(field(a, 1).(object)["id"].([]byte)): true}
	for i := 0; i < 2; i++ {
		m := response(t, command(e, context.Background(), "a", 1, 8, nil))
		id := string(field(m, 1).(object)["id"].([]byte))
		if seen[id] {
			t.Fatal("duplicate continuation")
		}
		seen[id] = true
	}
	if got := command(e, context.Background(), "a", 1, 8, nil); got[0] != 0x30 {
		t.Fatal("continuation not exhausted")
	}
	if calls.Load() != 4 {
		t.Fatal("continuation asked for a separate approval")
	}
	for _, change := range []string{"cid", "session", "expiry", "replace", "intervening"} {
		t.Run(change, func(t *testing.T) {
			response(t, command(e, context.Background(), "a", 1, 2, assertionRequest("example.test")))
			session := "a"
			cid := uint32(1)
			switch change {
			case "cid":
				cid = 2
			case "session":
				session = "b"
			case "expiry":
				e.now = func() time.Time { return time.Now().Add(time.Minute) }
			case "replace":
				blob, gen, _ := e.Snapshot()
				if err := e.Replace(blob, gen); err != nil {
					t.Fatal(err)
				}
			case "intervening":
				response(t, command(e, context.Background(), "a", 1, 4, nil))
			}
			if got := command(e, context.Background(), session, cid, 8, nil); got[0] != 0x30 {
				t.Fatalf("stale continuation %x", got)
			}
			e.now = time.Now
		})
	}
}

func TestCancellationBusyAndConcurrentManagement(t *testing.T) {
	e, _, _ := testEngine(t)
	started := make(chan struct{})
	e.approve = func(ctx context.Context, _ Approval) error { close(started); <-ctx.Done(); return ctx.Err() }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan []byte, 1)
	go func() { done <- command(e, ctx, "a", 1, 1, makeRequest("example.test", "one", false)) }()
	<-started
	if got := command(e, context.Background(), "b", 2, 4, nil); got[0] != 6 {
		t.Fatalf("concurrent request %x", got)
	}
	if e.Status().CredentialCount != 0 {
		t.Fatal("pending operation published")
	}
	blob, gen, err := e.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Replace(blob, gen); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case got := <-done:
		if got[0] != 0x2d {
			t.Fatalf("cancel %x", got)
		}
	case <-time.After(time.Second):
		t.Fatal("approval did not cancel")
	}
	started = make(chan struct{})
	release := make(chan struct{})
	e.approve = func(context.Context, Approval) error { close(started); <-release; return nil }
	go func() { done <- command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "two", false)) }()
	<-started
	blob, gen, _ = e.Snapshot()
	if err = e.Replace(blob, gen); err != nil {
		t.Fatal(err)
	}
	close(release)
	if got := <-done; got[0] != 0x30 {
		t.Fatalf("management raced stale approval: %x", got)
	}
	if e.Status().CredentialCount != 0 {
		t.Fatal("store changed during stale approval")
	}
}

func TestStoreCASCounterRollbackAndWriteFailures(t *testing.T) {
	e, _, path := testEngine(t)
	response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "one", false)))
	old, gen, _ := e.Snapshot()
	response(t, command(e, context.Background(), "a", 1, 2, assertionRequest("example.test")))
	if err := e.Replace(old, gen); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS %v", err)
	}
	_, current, _ := e.Snapshot()
	if err := e.Replace(old, current); !errors.Is(err, ErrCounterRollback) {
		t.Fatalf("counter rollback %v", err)
	}
	before := e.Status()
	onDisk, _ := os.ReadFile(path)
	writer := e.write
	e.write = func([]byte) error { return errors.New("injected fsync failure") }
	if got := command(e, context.Background(), "a", 1, 2, assertionRequest("example.test")); len(got) != 1 || got[0] != 0x7f {
		t.Fatalf("released signature after failed persist %x", got)
	}
	after := e.Status()
	if before.Generation != after.Generation || before.CredentialCount != after.CredentialCount {
		t.Fatal("failed assertion published state")
	}
	now, _ := os.ReadFile(path)
	if !bytes.Equal(onDisk, now) {
		t.Fatal("failure rewrote disk")
	}
	e.write = writer
	if got := command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "two", false)); got[0] != 0x7f {
		t.Fatal("uncertain persistence state did not fail closed")
	}
	if e.Status().CredentialCount != 1 {
		t.Fatal("failed registration published credential")
	}
	if after.LastError == "" {
		t.Fatal("write failure missing from status")
	}
}

func fixedStore(t *testing.T) store {
	t.Helper()
	s, err := newStore()
	if err != nil {
		t.Fatal(err)
	}
	s.Counter = 123
	for i := range s.AAGUID {
		s.AAGUID[i] = byte(i)
	}
	c := &s.Credentials[0]
	c.Used = true
	c.Resident = true
	c.RPID = "legacy.test"
	c.Name = "legacy"
	c.Display = "Legacy User"
	c.UserID = []byte{1, 2, 3}
	c.ID[0] = 0xa9
	c.Private[31] = 1
	x, y := elliptic.P256().ScalarBaseMult(c.Private[:])
	x.FillBytes(c.Public[:32])
	y.FillBytes(c.Public[32:])
	for i := range c.HMACSecret {
		c.HMACSecret[i] = byte(i + 1)
	}
	return s
}
func legacyBlob(s store, version int, legacyCRC bool) []byte {
	b := s.encode()
	if version == 1 {
		old := b
		b = make([]byte, legacyStoreSize)
		copy(b, old[:storeHeader])
		for i := 0; i < maxCredentials; i++ {
			copy(b[storeHeader+i*legacyCredentialSize:], old[storeHeader+i*credentialSize:storeHeader+i*credentialSize+legacyCredentialSize])
		}
		binary.LittleEndian.PutUint32(b[4:], 1)
	}
	crc := crc32.ChecksumIEEE(b[12:])
	if legacyCRC {
		crc = ^crc32.Update(^uint32(0), crc32.IEEETable, b[12:])
	}
	binary.LittleEndian.PutUint32(b[8:], crc)
	return b
}
func TestLegacyStoreVersionsAndKernelCRCVariants(t *testing.T) {
	for _, version := range []int{1, 2} {
		for _, oldCRC := range []bool{false, true} {
			t.Run(string(rune('0'+version))+map[bool]string{false: "normal", true: "legacy"}[oldCRC], func(t *testing.T) {
				s := fixedStore(t)
				raw := legacyBlob(s, version, oldCRC)
				path := filepath.Join(t.TempDir(), "legacy.bin")
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				e, err := New(path, func(context.Context, Approval) error { return nil })
				if err != nil {
					t.Fatal(err)
				}
				snapshot, _, _ := e.Snapshot()
				migrated, err := parseStore(snapshot)
				if err != nil {
					t.Fatal(err)
				}
				if migrated.AAGUID != s.AAGUID || migrated.Counter != 123 || migrated.Credentials[0].Private != s.Credentials[0].Private || migrated.Credentials[0].Public != s.Credentials[0].Public || migrated.Credentials[0].ID != s.Credentials[0].ID {
					t.Fatal("legacy identity changed")
				}
				if version == 1 && !allZero(migrated.Credentials[0].HMACSecret[:]) {
					t.Fatal("v1 secret invented")
				}
				if version == 2 && migrated.Credentials[0].HMACSecret != s.Credentials[0].HMACSecret {
					t.Fatal("v2 secret lost")
				}
				m := response(t, command(e, context.Background(), "a", 1, 2, assertionRequest("legacy.test")))
				ad := field(m, 2).([]byte)
				pubKey, _ := s.Credentials[0].key()
				verify(t, &pubKey.PublicKey, ad, bytes.Repeat([]byte{0x7a}, 32), field(m, 3).([]byte))
				if binary.BigEndian.Uint32(ad[33:]) != 124 {
					t.Fatal("legacy counter reset")
				}
			})
		}
	}
}
func TestRejectCorruptStoreWithoutReset(t *testing.T) {
	s := fixedStore(t)
	for _, kind := range []string{"crc", "point", "scalar", "duplicate", "length"} {
		t.Run(kind, func(t *testing.T) {
			b := s.encode()
			switch kind {
			case "crc":
				b[8] ^= 1
			case "point":
				b[storeHeader+388] ^= 1
				binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[12:]))
			case "scalar":
				clear(b[storeHeader+356 : storeHeader+388])
				binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[12:]))
			case "duplicate":
				copy(b[storeHeader+credentialSize:], b[storeHeader:storeHeader+credentialSize])
				binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[12:]))
			case "length":
				b = append(b, 0)
			}
			path := filepath.Join(t.TempDir(), "bad.bin")
			os.WriteFile(path, b, 0600)
			if _, err := New(path, func(context.Context, Approval) error { return nil }); err == nil {
				t.Fatal("corrupt store accepted")
			}
			now, _ := os.ReadFile(path)
			if !bytes.Equal(now, b) {
				t.Fatal("corrupt store was silently replaced")
			}
		})
	}
}

func TestProtocolOneHMACSecretInteroperability(t *testing.T) {
	e, calls, _ := testEngine(t)
	mc := response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "one", true)))
	_, _, mcExt := inspectAuthData(t, field(mc, 2).([]byte))
	if mcExt["hmac-secret"] != true {
		t.Fatal("registration extension")
	}
	keyResp := response(t, command(e, context.Background(), "a", 1, 6, object{1: 1, 2: 2}))
	ka := field(keyResp, 1).(object)
	if field(ka, 3) != int64(-25) {
		t.Fatal("ECDH COSE algorithm")
	}
	point := append([]byte{4}, ka[int64(-2)].([]byte)...)
	point = append(point, ka[int64(-3)].([]byte)...)
	authPub, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		t.Fatal(err)
	}
	platform, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	z, err := platform.ECDH(authPub)
	if err != nil {
		t.Fatal(err)
	}
	shared := sha256.Sum256(z)
	blob, _, _ := e.Snapshot()
	s, err := parseStore(blob)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{32, 64} {
		t.Run(string(rune('0'+n/32))+"salts", func(t *testing.T) {
			salts := make([]byte, n)
			for i := range salts {
				salts[i] = byte(i + 9)
			}
			enc := bytes.Clone(salts)
			block, _ := aes.NewCipher(shared[:])
			cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(enc, enc)
			mac := hmac.New(sha256.New, shared[:])
			mac.Write(enc)
			tag := mac.Sum(nil)[:16]
			hm := object{1: coseKey(platform.PublicKey().Bytes()[1:], -25), 2: enc, 3: tag, 4: 1}
			req := assertionRequest("example.test")
			req[4] = object{"hmac-secret": hm}
			m := response(t, command(e, context.Background(), "a", 1, 2, req))
			ad := field(m, 2).([]byte)
			_, _, ext := inspectAuthData(t, ad)
			out := ext["hmac-secret"].([]byte)
			if len(out) != n || ad[32] != 0x85 {
				t.Fatal("extension flags/size")
			}
			plain := make([]byte, len(out))
			cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(plain, out)
			for i := 0; i < n; i += 32 {
				prf := hmac.New(sha256.New, s.Credentials[0].HMACSecret[:])
				prf.Write(salts[i : i+32])
				if !hmac.Equal(prf.Sum(nil), plain[i:i+32]) {
					t.Fatal("host PRF does not match")
				}
			}
			pub, _ := s.Credentials[0].key()
			verify(t, &pub.PublicKey, ad, req[2].([]byte), field(m, 3).([]byte))
			before := calls.Load()
			bad := bytes.Clone(tag)
			bad[0] ^= 1
			hm[3] = bad
			if got := command(e, context.Background(), "a", 1, 2, req); got[0] != 0x33 {
				t.Fatalf("bad saltAuth %x", got)
			}
			if calls.Load() != before {
				t.Fatal("malformed hmac prompted")
			}
			hm[3] = tag
			hm[4] = 2
			if got := command(e, context.Background(), "a", 1, 2, req); got[0] != 0x33 {
				t.Fatalf("unsupported protocol %x", got)
			}
			hm[4] = 1
			req[5] = object{"up": false}
			if got := command(e, context.Background(), "a", 1, 2, req); got[0] != 0x2b {
				t.Fatalf("silent hmac request %x", got)
			}
		})
	}
	if got := command(e, context.Background(), "a", 1, 6, object{1: 1, 2: 3}); got[0] != 1 {
		t.Fatalf("advertised nonexistent PIN command %x", got)
	}
	info := response(t, command(e, context.Background(), "a", 1, 4, nil))
	if !reflect.DeepEqual(field(info, 1), []any{"FIDO_2_0"}) || !reflect.DeepEqual(field(info, 6), []any{int64(1)}) {
		t.Fatal("unsupported version/protocol advertised")
	}
	if _, present := field(info, 4).(object)["clientPin"]; present {
		t.Fatal("PIN support advertised")
	}
}

func TestNameTruncationKeepsUTF8(t *testing.T) {
	e, _, _ := testEngine(t)
	req := makeRequest("example.test", strings.Repeat("名", 30), false)
	req[3].(object)["id"] = []byte{1}
	response(t, command(e, context.Background(), "a", 1, 1, req))
	blob, _, _ := e.Snapshot()
	s, err := parseStore(blob)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Credentials[0].Name) != 63 {
		t.Fatal("UTF8 name truncation")
	}
}

func TestCBORBoundsAndCanonicalOutput(t *testing.T) {
	for _, b := range [][]byte{{0xa2, 1, 1, 1, 2}, {0x58, 0xff}, {0x18, 1}, {0x61, 0xff}, {0x9f, 0xff}, {0xc1, 0}, {0x01, 0}, {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		if _, err := decodeCBOR(b); err == nil {
			t.Fatalf("invalid CBOR accepted %x", b)
		}
	}
	nested := append(bytes.Repeat([]byte{0x81}, 18), 0)
	if _, err := decodeCBOR(nested); err == nil {
		t.Fatal("unbounded nesting")
	}
	canonical := encodeCBOR(object{int64(-1): 1, int64(24): 2, "x": true})
	if !bytes.Equal(canonical, []byte{0xa3, 0x18, 0x18, 2, 0x20, 1, 0x61, 'x', 0xf5}) {
		t.Fatalf("CTAP canonical order %x", canonical)
	}
	e, _, _ := testEngine(t)
	if got := e.Execute(context.Background(), "a", 1, []byte{1, 0xa2, 1, 1, 1, 2}); got[0] != 0x12 {
		t.Fatalf("bad request result %x", got)
	}
}

func TestSilentProbesNeverPromptOrReleaseSignatures(t *testing.T) {
	e, calls, _ := testEngine(t)
	response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "one", false)))
	before := calls.Load()
	for _, rp := range []string{"example.test", "missing.test"} {
		req := assertionRequest(rp)
		req[5] = object{"up": false}
		if got := command(e, context.Background(), "a", 1, 2, req); !bytes.Equal(got, []byte{0x3b}) {
			t.Fatalf("silent probe %x", got)
		}
	}
	if calls.Load() != before {
		t.Fatal("silent probe prompted")
	}
	blob, _, _ := e.Snapshot()
	s, _ := parseStore(blob)
	if s.Counter != 0 || !allZero(s.Credentials[0].HMACSecret[:]) {
		t.Fatal("probe signed or non-opt-in credential got secret")
	}
}

func TestUncertainDirectorySyncFailsClosedUntilRestart(t *testing.T) {
	e, _, path := testEngine(t)
	e.write = func(b []byte) error {
		if err := atomicWrite(path, b); err != nil {
			return err
		}
		return errors.New("injected error after rename")
	}
	got := command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "one", false))
	if !bytes.Equal(got, []byte{0x7f}) || e.Status().CredentialCount != 0 {
		t.Fatal("uncertain registration published")
	}
	e.write = func(b []byte) error { return atomicWrite(path, b) }
	if got = command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "two", false)); got[0] != 0x7f {
		t.Fatal("uncertain state retried")
	}
	reopened, err := New(path, func(context.Context, Approval) error { return nil })
	if err != nil || reopened.Status().CredentialCount != 1 {
		t.Fatalf("recovery lost durably renamed state: %v", err)
	}
}

func TestCancellationDuringPersistenceDoesNotPublishResponse(t *testing.T) {
	e, _, path := testEngine(t)
	ctx, cancel := context.WithCancel(context.Background())
	e.write = func(b []byte) error { err := atomicWrite(path, b); cancel(); return err }
	if got := command(e, ctx, "a", 1, 1, makeRequest("example.test", "one", false)); !bytes.Equal(got, []byte{0x2d}) {
		t.Fatalf("cancelled response %x", got)
	}
	// Persistence may complete concurrently with cancellation, but no key or
	// signature response may escape after it. The stored credential is safe to
	// retain and can be removed through the management UI.
	if e.Status().CredentialCount != 1 {
		t.Fatal("committed state not retained")
	}
}

func TestResetAndCounterExhaustion(t *testing.T) {
	e, _, _ := testEngine(t)
	response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "one", false)))
	blob, gen, _ := e.Snapshot()
	s, _ := parseStore(blob)
	oldAAGUID := s.AAGUID
	s.Counter = ^uint32(0)
	if err := e.Replace(s.encode(), gen); err != nil {
		t.Fatal(err)
	}
	if got := command(e, context.Background(), "a", 1, 2, assertionRequest("example.test")); !bytes.Equal(got, []byte{0x15}) {
		t.Fatalf("counter wrapped %x", got)
	}
	oldKey := bytes.Clone(e.keyAgreement.PublicKey().Bytes())
	if got := command(e, context.Background(), "a", 1, 7, nil); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("reset %x", got)
	}
	blob, _, _ = e.Snapshot()
	s, _ = parseStore(blob)
	if s.Counter != 0 || s.AAGUID != oldAAGUID || s.AAGUID != modelAAGUID || e.Status().CredentialCount != 0 || bytes.Equal(oldKey, e.keyAgreement.PublicKey().Bytes()) {
		t.Fatal("reset did not rotate authenticator state")
	}
}

func TestResetMigratedStoreUsesModelAAGUID(t *testing.T) {
	s := fixedStore(t)
	path := filepath.Join(t.TempDir(), "legacy.bin")
	if err := os.WriteFile(path, s.encode(), 0600); err != nil {
		t.Fatal(err)
	}
	e, err := New(path, func(context.Context, Approval) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := e.Snapshot()
	migrated, _ := parseStore(b)
	if migrated.AAGUID != s.AAGUID {
		t.Fatal("migration changed old AAGUID")
	}
	if got := command(e, context.Background(), "a", 1, 7, nil); !bytes.Equal(got, []byte{0}) {
		t.Fatalf("reset %x", got)
	}
	b, _, _ = e.Snapshot()
	reset, _ := parseStore(b)
	if reset.AAGUID != modelAAGUID || e.Status().CredentialCount != 0 {
		t.Fatal("reset retained obsolete model identity or credentials")
	}
}

func TestMigrateLegacyOnlyOnceAndPreserveBackup(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			dir := t.TempDir()
			legacy := filepath.Join(dir, "metadata", "old.bin")
			target := filepath.Join(dir, "data", "store.bin")
			if err := os.MkdirAll(filepath.Dir(legacy), 0700); err != nil {
				t.Fatal(err)
			}
			s := fixedStore(t)
			original := legacyBlob(s, version, true)
			if err := os.WriteFile(legacy, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := MigrateLegacy(target, legacy); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			imported, err := parseStore(b)
			if err != nil {
				t.Fatal(err)
			}
			if imported.AAGUID != s.AAGUID || imported.Counter != s.Counter || imported.Credentials[0].Private != s.Credentials[0].Private {
				t.Fatal("migration changed identity")
			}
			info, _ := os.Stat(target)
			if info.Mode().Perm() != 0600 {
				t.Fatal("migration permissions")
			}
			backup, _ := os.ReadFile(legacy)
			if !bytes.Equal(original, backup) {
				t.Fatal("migration modified legacy backup")
			}
			// The new single-writer store advances independently. Subsequent
			// starts must never overwrite it with this stale legacy snapshot.
			imported.Counter++
			if err := atomicWrite(target, imported.encode()); err != nil {
				t.Fatal(err)
			}
			if err := MigrateLegacy(target, legacy); err != nil {
				t.Fatal(err)
			}
			b, _ = os.ReadFile(target)
			after, _ := parseStore(b)
			if after.Counter != s.Counter+1 {
				t.Fatal("repeat migration rolled back counter")
			}
			if err := os.WriteFile(target, nil, 0600); err != nil {
				t.Fatal(err)
			}
			if err := MigrateLegacy(target, legacy); err != nil {
				t.Fatal(err)
			}
			if info, _ = os.Stat(target); info.Size() != 0 {
				t.Fatal("damaged existing destination was overwritten")
			}
			if _, err := New(target, func(context.Context, Approval) error { return nil }); err == nil {
				t.Fatal("damaged destination silently reset")
			}
		})
	}
}

func TestMigrateLegacyAbsentAndInvalidInput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "new", "store.bin")
	old := filepath.Join(dir, "old.bin")
	if err := MigrateLegacy(target, old); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing backup created a destination")
	}
	for _, bad := range [][]byte{{}, {1, 2, 3}, bytes.Repeat([]byte{0}, storeSize)} {
		if err := os.WriteFile(old, bad, 0600); err != nil {
			t.Fatal(err)
		}
		if err := MigrateLegacy(target, old); err == nil {
			t.Fatal("invalid legacy store imported")
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid input created store")
		}
	}
	s := fixedStore(t)
	blob := s.encode()
	blob[storeHeader+356] ^= 0x77
	binary.LittleEndian.PutUint32(blob[8:], crc32.ChecksumIEEE(blob[12:]))
	os.WriteFile(old, blob, 0600)
	if err := MigrateLegacy(target, old); err == nil {
		t.Fatal("invalid legacy key imported")
	}
}

func TestExclusiveMigrationPublishDoesNotOverwriteExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.bin")
	existing := []byte("existing destination")
	if err := os.WriteFile(path, existing, 0600); err != nil {
		t.Fatal(err)
	}
	if err := atomicPersist(path, []byte("different store"), false); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !bytes.Equal(b, existing) {
		t.Fatal("exclusive publish overwrote destination")
	}
}

func TestResidentReregistrationReplacesOnlySameRPAndUser(t *testing.T) {
	e, _, _ := testEngine(t)
	req := makeRequest("example.test", "one", true)
	m := response(t, command(e, context.Background(), "a", 1, 1, req))
	_, oldID, _ := inspectAuthData(t, field(m, 2).([]byte))
	m = response(t, command(e, context.Background(), "a", 1, 1, req))
	_, newID, _ := inspectAuthData(t, field(m, 2).([]byte))
	if bytes.Equal(oldID, newID) || e.Status().CredentialCount != 1 {
		t.Fatal("resident registration was not replaced")
	}
	old := assertionRequest("example.test")
	old[3] = []any{object{"id": oldID, "type": "public-key"}}
	if got := command(e, context.Background(), "a", 1, 2, old); got[0] != 0x2e {
		t.Fatalf("superseded credential still signs %x", got)
	}
	current := assertionRequest("example.test")
	current[3] = []any{object{"id": newID, "type": "public-key"}}
	response(t, command(e, context.Background(), "a", 1, 2, current))
	response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "two", false)))
	response(t, command(e, context.Background(), "a", 1, 1, makeRequest("other.test", "one", false)))
	if e.Status().CredentialCount != 3 {
		t.Fatal("different RP or user was replaced")
	}
	// Exclude still takes precedence over the replacement rule.
	req[5] = []any{object{"id": newID, "type": "public-key"}}
	if got := command(e, context.Background(), "a", 1, 1, req); got[0] != 0x19 {
		t.Fatalf("replacement ignored exclusion %x", got)
	}
}

func TestFullResidentStoreCanUpdateExistingAccount(t *testing.T) {
	e, _, _ := testEngine(t)
	for i := 0; i < maxCredentials; i++ {
		response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", fmt.Sprintf("user%02d", i), false)))
	}
	if e.Status().CredentialCount != maxCredentials {
		t.Fatal("store did not fill")
	}
	if got := command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "extra", false)); got[0] != 0x28 {
		t.Fatalf("full store accepted new account %x", got)
	}
	response(t, command(e, context.Background(), "a", 1, 1, makeRequest("example.test", "user00", true)))
	if e.Status().CredentialCount != maxCredentials {
		t.Fatal("full-store update changed count")
	}
}

func TestNonResidentRegistrationDoesNotReplace(t *testing.T) {
	e, _, _ := testEngine(t)
	req := makeRequest("example.test", "one", false)
	req[7] = object{"rk": false}
	for i := 0; i < 2; i++ {
		response(t, command(e, context.Background(), "a", 1, 1, req))
	}
	if e.Status().CredentialCount != 2 {
		t.Fatal("non-resident credentials were replaced")
	}
	req[7] = object{"rk": true}
	response(t, command(e, context.Background(), "a", 1, 1, req))
	response(t, command(e, context.Background(), "a", 1, 1, req))
	if e.Status().CredentialCount != 3 {
		t.Fatal("resident registration replaced a non-resident key")
	}
}

func TestMissingCredentialRequiresApprovalBeforeDisclosure(t *testing.T) {
	e, calls, _ := testEngine(t)
	req := assertionRequest("unknown.test")
	if got := command(e, context.Background(), "a", 1, 2, req); !bytes.Equal(got, []byte{0x2e}) {
		t.Fatalf("approved missing credential %x", got)
	}
	if calls.Load() != 1 {
		t.Fatal("missing credential bypassed local approval")
	}
	e.approve = func(context.Context, Approval) error { calls.Add(1); return errors.New("denied") }
	if got := command(e, context.Background(), "a", 1, 2, req); !bytes.Equal(got, []byte{0x27}) {
		t.Fatalf("denial revealed credential presence %x", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.approve = func(context.Context, Approval) error { calls.Add(1); cancel(); return nil }
	if got := command(e, ctx, "a", 1, 2, req); !bytes.Equal(got, []byte{0x2d}) {
		t.Fatalf("cancellation revealed credential presence %x", got)
	}
	if calls.Load() != 3 {
		t.Fatal("missing-credential decisions skipped approval")
	}
}

func TestReregisterRetiresAllLegacyResidentDuplicatesAtomically(t *testing.T) {
	s := fixedStore(t)
	first := s.Credentials[0]
	for i := 1; i < 5; i++ {
		s.Credentials[i] = first
		s.Credentials[i].ID[0] = byte(0xa9 + i)
	}
	// Slot 1 duplicates the legacy account under a different credential ID.
	// The other entries must all survive this account's re-registration.
	s.Credentials[2].RPID = "different.test"
	s.Credentials[3].UserID = []byte{9, 8, 7}
	s.Credentials[4].Resident = false
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.bin")
	path := filepath.Join(dir, "new", "store.bin")
	if err := os.WriteFile(legacy, s.encode(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacy(path, legacy); err != nil {
		t.Fatal(err)
	}
	e, err := New(path, func(context.Context, Approval) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if e.Status().CredentialCount != 5 {
		t.Fatal("migration silently deduplicated existing keys")
	}
	req := makeRequest("legacy.test", "replacement", false)
	req[3].(object)["id"] = bytes.Clone(first.UserID)
	// A failed durable update must not retire any of the old IDs in memory
	// or on disk. Recovery reloads the complete original set.
	before, _, _ := e.Snapshot()
	e.write = func([]byte) error { return errors.New("injected persistence failure") }
	if got := command(e, context.Background(), "a", 1, 1, req); got[0] != 0x7f {
		t.Fatalf("failed replacement %x", got)
	}
	after, _, _ := e.Snapshot()
	disk, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || !bytes.Equal(before, disk) {
		t.Fatal("failed replacement partially retired old keys")
	}
	e, err = New(path, func(context.Context, Approval) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	m := response(t, command(e, context.Background(), "a", 1, 1, req))
	_, newID, _ := inspectAuthData(t, field(m, 2).([]byte))
	if e.Status().CredentialCount != 4 {
		t.Fatal("legacy duplicate account not fully replaced")
	}
	for _, old := range s.Credentials[:2] {
		a := assertionRequest(old.RPID)
		a[3] = []any{object{"id": old.ID[:], "type": "public-key"}}
		if got := command(e, context.Background(), "a", 1, 2, a); got[0] != 0x2e {
			t.Fatalf("old duplicate still signs %x", got)
		}
	}
	for _, preserved := range s.Credentials[2:5] {
		a := assertionRequest(preserved.RPID)
		a[3] = []any{object{"id": preserved.ID[:], "type": "public-key"}}
		response(t, command(e, context.Background(), "a", 1, 2, a))
	}
	a := assertionRequest("legacy.test")
	a[3] = []any{object{"id": newID, "type": "public-key"}}
	response(t, command(e, context.Background(), "a", 1, 2, a))
	final, _, _ := e.Snapshot()
	if !allZero(final[storeHeader+credentialSize : storeHeader+2*credentialSize]) {
		t.Fatal("retired duplicate slot retains key material")
	}
}

func FuzzCBORDoesNotPanic(f *testing.F) {
	for _, b := range [][]byte{{0xa0}, {0xa1, 1, 0x58, 32}, encodeCBOR(makeRequest("example.test", "one", true)), {0x9f, 0xff}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := decodeCBOR(b)
		if err == nil {
			canonical := encodeCBOR(v)
			if _, err = decodeCBOR(canonical); err != nil {
				t.Fatal(err)
			}
		}
	})
}
