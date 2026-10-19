package authenticator

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sort"
	"unicode/utf8"
)

// CTAP uses definite-length CBOR without tags or floating point values. Keep
// both allocation and nesting bounded before allocating host-controlled data.
const maxMessage = 4096

type object map[any]any

func decodeCBOR(b []byte) (any, error) {
	if len(b) > maxMessage {
		return nil, errors.New("CBOR message too large")
	}
	r := cborReader{b: b}
	v, err := r.value(0)
	if err == nil && r.p != len(b) {
		err = errors.New("trailing CBOR data")
	}
	return v, err
}

type cborReader struct {
	b []byte
	p int
}

func (r *cborReader) value(depth int) (any, error) {
	bad := func() (any, error) { return nil, errors.New("invalid CBOR") }
	if depth > 16 || r.p >= len(r.b) {
		return bad()
	}
	h := r.b[r.p]
	r.p++
	major, ai := h>>5, h&31
	n := uint64(ai)
	if ai >= 24 {
		var width int
		switch ai {
		case 24:
			width = 1
		case 25:
			width = 2
		case 26:
			width = 4
		case 27:
			width = 8
		default:
			return bad()
		}
		if width > len(r.b)-r.p {
			return bad()
		}
		n = 0
		for _, v := range r.b[r.p : r.p+width] {
			n = n<<8 | uint64(v)
		}
		r.p += width
		if n < 24 || (width > 1 && n <= 0xff) || (width > 2 && n <= 0xffff) || (width > 4 && n <= 0xffffffff) {
			return bad()
		}
	}
	switch major {
	case 0, 1:
		if n > math.MaxInt64 {
			return bad()
		}
		if major == 1 {
			return -1 - int64(n), nil
		}
		return int64(n), nil
	case 2, 3:
		if n > uint64(len(r.b)-r.p) {
			return bad()
		}
		v := r.b[r.p : r.p+int(n)]
		r.p += int(n)
		if major == 3 {
			if !utf8.Valid(v) {
				return bad()
			}
			return string(v), nil
		}
		return bytes.Clone(v), nil
	case 4:
		if n > uint64(len(r.b)-r.p) {
			return bad()
		}
		v := make([]any, 0, int(n))
		for i := uint64(0); i < n; i++ {
			item, e := r.value(depth + 1)
			if e != nil {
				return nil, e
			}
			v = append(v, item)
		}
		return v, nil
	case 5:
		if n > uint64((len(r.b)-r.p)/2) {
			return bad()
		}
		v := make(object, int(n))
		for i := uint64(0); i < n; i++ {
			key, e := r.value(depth + 1)
			if e != nil {
				return nil, e
			}
			switch key.(type) {
			case int64, string:
			default:
				return bad()
			}
			if _, exists := v[key]; exists {
				return bad()
			}
			item, e := r.value(depth + 1)
			if e != nil {
				return nil, e
			}
			v[key] = item
		}
		return v, nil
	case 7:
		if ai == 20 {
			return false, nil
		}
		if ai == 21 {
			return true, nil
		}
		if ai == 22 {
			return nil, nil
		}
	}
	return bad()
}

func encodeCBOR(v any) []byte {
	var b []byte
	var head func(byte, uint64)
	head = func(major byte, n uint64) {
		switch {
		case n < 24:
			b = append(b, major<<5|byte(n))
		case n <= 0xff:
			b = append(b, major<<5|24, byte(n))
		case n <= 0xffff:
			b = append(b, major<<5|25, byte(n>>8), byte(n))
		case n <= 0xffffffff:
			b = append(b, major<<5|26)
			b = binary.BigEndian.AppendUint32(b, uint32(n))
		default:
			b = append(b, major<<5|27)
			b = binary.BigEndian.AppendUint64(b, n)
		}
	}
	var put func(any)
	put = func(v any) {
		switch x := v.(type) {
		case nil:
			b = append(b, 0xf6)
		case bool:
			if x {
				b = append(b, 0xf5)
			} else {
				b = append(b, 0xf4)
			}
		case int:
			put(int64(x))
		case uint32:
			head(0, uint64(x))
		case int64:
			if x >= 0 {
				head(0, uint64(x))
			} else {
				head(1, uint64(-1-x))
			}
		case []byte:
			head(2, uint64(len(x)))
			b = append(b, x...)
		case string:
			head(3, uint64(len(x)))
			b = append(b, x...)
		case []any:
			head(4, uint64(len(x)))
			for _, item := range x {
				put(item)
			}
		case object:
			type pair struct {
				k []byte
				v any
			}
			pairs := make([]pair, 0, len(x))
			for key, val := range x {
				pairs = append(pairs, pair{encodeCBOR(key), val})
			}
			// CTAP2 canonical order is the bytewise order of encoded keys
			// (major type first), rather than RFC 7049's length-first order.
			sort.Slice(pairs, func(i, j int) bool { return bytes.Compare(pairs[i].k, pairs[j].k) < 0 })
			head(5, uint64(len(pairs)))
			for _, p := range pairs {
				b = append(b, p.k...)
				put(p.v)
			}
		default:
			panic("unsupported internal CBOR value")
		}
	}
	put(v)
	return b
}
