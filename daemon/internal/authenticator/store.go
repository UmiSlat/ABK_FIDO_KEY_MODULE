package authenticator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math/big"
	"os"
	"path/filepath"
	"unicode/utf8"
)

const (
	storeMagic           = 0x41424646
	storeHeader          = 84
	credentialSize       = 484
	legacyCredentialSize = 452
	maxCredentials       = 32
	storeSize            = storeHeader + credentialSize*maxCredentials
	legacyStoreSize      = storeHeader + legacyCredentialSize*maxCredentials
)

// AAGUID identifies this authenticator implementation, not an individual key
// or a credential secret. Existing stores retain their historical AAGUID.
var modelAAGUID = [16]byte{0x8d, 0xc9, 0x4f, 0x6e, 0x75, 0x24, 0x4a, 0x6f, 0x98, 0x8e, 0x23, 0xb7, 0x11, 0x6d, 0x50, 0x42}

type credential struct {
	Used, Resident      bool
	ID                  [32]byte
	UserID              []byte
	RPID, Name, Display string
	Private             [32]byte
	Public              [64]byte
	HMACSecret          [32]byte
}
type store struct {
	Header      [storeHeader]byte
	Counter     uint32
	AAGUID      [16]byte
	Credentials [maxCredentials]credential
}

func newStore() (store, error) {
	var s store
	s.AAGUID = modelAAGUID
	if _, err := rand.Read(s.Header[52:84]); err != nil {
		return s, err
	}
	s.Header[33] = 8
	return s, nil
}

func parseStore(b []byte) (store, error) {
	var s store
	if len(b) < storeHeader || binary.LittleEndian.Uint32(b) != storeMagic {
		return s, errors.New("invalid store magic or size")
	}
	version := binary.LittleEndian.Uint32(b[4:8])
	width := credentialSize
	size := storeSize
	if version == 1 {
		width = legacyCredentialSize
		size = legacyStoreSize
	} else if version != 2 {
		return s, errors.New("unsupported store version")
	}
	if len(b) != size {
		return s, errors.New("invalid store length")
	}
	crc := binary.LittleEndian.Uint32(b[8:12])
	data := b[12:]
	// Older kernel revisions used crc32_le(0,...) without complements.
	if crc32.ChecksumIEEE(data) != crc && ^crc32.Update(^uint32(0), crc32.IEEETable, data) != crc {
		return s, errors.New("invalid store CRC32")
	}
	copy(s.Header[:], b[:storeHeader])
	s.Counter = binary.LittleEndian.Uint32(b[12:16])
	copy(s.AAGUID[:], b[16:32])
	seen := make(map[[32]byte]bool)
	for i := range s.Credentials {
		d := b[storeHeader+i*width : storeHeader+(i+1)*width]
		c := &s.Credentials[i]
		if d[0] == 0 {
			continue
		}
		if d[0] != 1 || d[1] > 1 || d[2] == 0 || d[2] > 64 {
			return s, fmt.Errorf("invalid credential slot %d", i)
		}
		c.Used = true
		c.Resident = d[1] == 1
		copy(c.ID[:], d[4:36])
		c.UserID = bytes.Clone(d[36 : 36+int(d[2])])
		var err error
		if c.RPID, err = readCString(d[100:228]); err != nil || c.RPID == "" {
			return s, fmt.Errorf("invalid RP in slot %d", i)
		}
		if c.Name, err = readCString(d[228:292]); err != nil {
			return s, err
		}
		if c.Display, err = readCString(d[292:356]); err != nil {
			return s, err
		}
		copy(c.Private[:], d[356:388])
		copy(c.Public[:], d[388:452])
		if version == 2 {
			copy(c.HMACSecret[:], d[452:484])
		}
		if _, err = c.key(); err != nil {
			return s, fmt.Errorf("invalid P-256 key in slot %d: %w", i, err)
		}
		if seen[c.ID] {
			return s, errors.New("duplicate credential ID")
		}
		seen[c.ID] = true
	}
	return s, nil
}

func readCString(b []byte) (string, error) {
	i := bytes.IndexByte(b, 0)
	if i < 0 || !utf8.Valid(b[:i]) {
		return "", errors.New("invalid store string")
	}
	return string(b[:i]), nil
}

func (s *store) encode() []byte {
	b := make([]byte, storeSize)
	copy(b, s.Header[:])
	binary.LittleEndian.PutUint32(b, storeMagic)
	binary.LittleEndian.PutUint32(b[4:], 2)
	binary.LittleEndian.PutUint32(b[12:], s.Counter)
	copy(b[16:32], s.AAGUID[:])
	for i, c := range s.Credentials {
		if !c.Used {
			continue
		}
		d := b[storeHeader+i*credentialSize : storeHeader+(i+1)*credentialSize]
		d[0] = 1
		if c.Resident {
			d[1] = 1
		}
		d[2] = byte(len(c.UserID))
		copy(d[4:36], c.ID[:])
		copy(d[36:100], c.UserID)
		copy(d[100:228], c.RPID)
		copy(d[228:292], c.Name)
		copy(d[292:356], c.Display)
		copy(d[356:388], c.Private[:])
		copy(d[388:452], c.Public[:])
		copy(d[452:484], c.HMACSecret[:])
	}
	binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[12:]))
	return b
}

func (c *credential) key() (*ecdsa.PrivateKey, error) {
	d := new(big.Int).SetBytes(c.Private[:])
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 {
		return nil, errors.New("private scalar out of range")
	}
	x, y := curve.ScalarBaseMult(c.Private[:])
	px := new(big.Int).SetBytes(c.Public[:32])
	py := new(big.Int).SetBytes(c.Public[32:])
	if !curve.IsOnCurve(px, py) || x.Cmp(px) != 0 || y.Cmp(py) != 0 {
		return nil, errors.New("public key does not match private scalar")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d}, nil
}

// MigrateLegacy imports a validated kernel store once. An existing destination
// always wins, including a damaged one: New must report that damage rather
// than silently restoring an older backup with a lower signature counter.
// Call this after obtaining the daemon's process lock and before New.
func MigrateLegacy(destination, legacy string) error {
	if !filepath.IsAbs(destination) || !filepath.IsAbs(legacy) {
		return errors.New("absolute migration paths are required")
	}
	if _, err := os.Lstat(destination); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	info, err := os.Lstat(legacy)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || (info.Size() != storeSize && info.Size() != legacyStoreSize) {
		return errors.New("invalid legacy store type or length")
	}
	b, err := os.ReadFile(legacy)
	if err != nil {
		return err
	}
	s, err := parseStore(b)
	if err != nil {
		return fmt.Errorf("legacy store validation failed: %w", err)
	}
	return atomicPersist(destination, s.encode(), false)
}

func atomicWrite(path string, b []byte) error {
	return atomicPersist(path, b, true)
}

func atomicPersist(path string, b []byte, replace bool) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".abk-fido-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if replace {
		if err = os.Rename(name, path); err != nil {
			return err
		}
	} else {
		// Link publishes the complete, fsynced inode with exclusive creation.
		// Unlike rename, it cannot overwrite a destination created after Lstat.
		if err = os.Link(name, path); errors.Is(err, os.ErrExist) {
			return nil
		} else if err != nil {
			return err
		}
		if err = os.Remove(name); err != nil {
			return err
		}
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
