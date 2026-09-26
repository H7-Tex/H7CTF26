package main

import (
	"errors"
	"math/big"
)

type cborReader struct {
	buf []byte
	pos int
}

var errCbor = errors.New("cbor")

func (r *cborReader) readByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, errCbor
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

func (r *cborReader) readN(n int) ([]byte, error) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, errCbor
	}
	out := r.buf[r.pos : r.pos+n]
	r.pos += n
	return out, nil
}

func (r *cborReader) readUint(ai byte) (uint64, error) {
	switch {
	case ai < 24:
		return uint64(ai), nil
	case ai == 24:
		b, err := r.readByte()
		return uint64(b), err
	case ai == 25:
		p, err := r.readN(2)
		if err != nil {
			return 0, err
		}
		return uint64(p[0])<<8 | uint64(p[1]), nil
	case ai == 26:
		p, err := r.readN(4)
		if err != nil {
			return 0, err
		}
		return uint64(p[0])<<24 | uint64(p[1])<<16 | uint64(p[2])<<8 | uint64(p[3]), nil
	case ai == 27:
		p, err := r.readN(8)
		if err != nil {
			return 0, err
		}
		var v uint64
		for _, x := range p {
			v = v<<8 | uint64(x)
		}
		return v, nil
	}
	return 0, errCbor
}

func (r *cborReader) decode() (interface{}, error) {
	b, err := r.readByte()
	if err != nil {
		return nil, err
	}
	major := b >> 5
	ai := b & 0x1f
	switch major {
	case 0:
		v, err := r.readUint(ai)
		if err != nil {
			return nil, err
		}
		return int64(v), nil
	case 1:
		v, err := r.readUint(ai)
		if err != nil {
			return nil, err
		}
		if v > uint64(1<<62) {
			n := new(big.Int).SetUint64(v)
			n.Neg(n).Sub(n, big.NewInt(1))
			return n, nil
		}
		return -1 - int64(v), nil
	case 2:
		n, err := r.readUint(ai)
		if err != nil {
			return nil, err
		}
		p, err := r.readN(int(n))
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(p))
		copy(out, p)
		return out, nil
	case 3:
		n, err := r.readUint(ai)
		if err != nil {
			return nil, err
		}
		p, err := r.readN(int(n))
		if err != nil {
			return nil, err
		}
		return string(p), nil
	case 4:
		n, err := r.readUint(ai)
		if err != nil {
			return nil, err
		}
		arr := make([]interface{}, 0, n)
		for i := uint64(0); i < n; i++ {
			e, err := r.decode()
			if err != nil {
				return nil, err
			}
			arr = append(arr, e)
		}
		return arr, nil
	case 5:
		n, err := r.readUint(ai)
		if err != nil {
			return nil, err
		}
		m := map[interface{}]interface{}{}
		for i := uint64(0); i < n; i++ {
			k, err := r.decode()
			if err != nil {
				return nil, err
			}
			v, err := r.decode()
			if err != nil {
				return nil, err
			}
			m[normalizeKey(k)] = v
		}
		return m, nil
	}
	return nil, errCbor
}

func normalizeKey(k interface{}) interface{} {
	switch v := k.(type) {
	case string:
		return v
	case int64:
		return v
	}
	return k
}

func cborDecode(data []byte) (interface{}, error) {
	r := &cborReader{buf: data}
	v, err := r.decode()
	if err != nil {
		return nil, err
	}
	return v, nil
}
