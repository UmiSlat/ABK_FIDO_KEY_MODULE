package authenticator

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
)

// PIN/UV protocol one is used solely for hmac-secret key agreement. This
// authenticator has built-in UV and deliberately implements no client PIN.
func (e *Engine) clientPIN(req object) (any, error) {
	protocol, err := intValue(req, 1, true)
	if err != nil {
		return nil, err
	}
	if protocol != 1 {
		return nil, invalidParameter
	}
	sub, err := intValue(req, 2, true)
	if err != nil {
		return nil, err
	}
	if sub != 2 {
		return nil, invalidCommand
	}
	return object{1: coseKey(e.keyAgreement.PublicKey().Bytes()[1:], -25)}, nil
}

type hmacRequest struct {
	shared [32]byte
	salts  []byte
}

func (e *Engine) parseHMAC(ext object) (*hmacRequest, error) {
	v, present := value(ext, "hmac-secret")
	if !present {
		return nil, nil
	}
	m, ok := v.(object)
	if !ok {
		return nil, unexpectedType
	}
	if _, present = value(m, 4); present {
		protocol, err := intValue(m, 4, true)
		if err != nil {
			return nil, err
		}
		if protocol != 1 {
			return nil, pinAuthInvalid
		}
	}
	ka, err := mapValue(m, 1, true)
	if err != nil {
		return nil, err
	}
	for _, p := range []struct {
		k int
		n int64
	}{{1, 2}, {3, -25}, {-1, 1}} {
		n, err := intValue(ka, p.k, true)
		if err != nil {
			return nil, err
		}
		if n != p.n {
			return nil, invalidParameter
		}
	}
	x, err := bytesValue(ka, -2, 32, 32, true)
	if err != nil {
		return nil, err
	}
	y, err := bytesValue(ka, -3, 32, 32, true)
	if err != nil {
		return nil, err
	}
	point := append([]byte{4}, x...)
	point = append(point, y...)
	peer, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return nil, invalidParameter
	}
	z, err := e.keyAgreement.ECDH(peer)
	if err != nil {
		return nil, invalidParameter
	}
	shared := sha256.Sum256(z)
	enc, err := bytesValue(m, 2, 32, 64, true)
	if err != nil {
		return nil, err
	}
	if len(enc) != 32 && len(enc) != 64 {
		return nil, invalidParameter
	}
	tag, err := bytesValue(m, 3, 16, 16, true)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, shared[:])
	mac.Write(enc)
	if !hmac.Equal(mac.Sum(nil)[:16], tag) {
		return nil, pinAuthInvalid
	}
	salts := make([]byte, len(enc))
	block, err := aes.NewCipher(shared[:])
	if err != nil {
		return nil, err
	}
	cipher.NewCBCDecrypter(block, make([]byte, 16)).CryptBlocks(salts, enc)
	return &hmacRequest{shared: shared, salts: salts}, nil
}

func (r *hmacRequest) output(secret []byte) ([]byte, error) {
	// Every assertion performs built-in UV and sets UV=1. The legacy store's
	// single secret is therefore always CredRandomWithUV; a non-UV branch is
	// never exposed and cannot accidentally disclose the same PRF namespace.
	out := make([]byte, 0, len(r.salts))
	for offset := 0; offset < len(r.salts); offset += 32 {
		mac := hmac.New(sha256.New, secret)
		mac.Write(r.salts[offset : offset+32])
		out = append(out, mac.Sum(nil)...)
	}
	block, err := aes.NewCipher(r.shared[:])
	if err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(out, out)
	return out, nil
}
