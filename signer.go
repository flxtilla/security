package security

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"hash"
	"time"
)

const (
	itsDangerousEpoch = 1293840000
)

type Signer interface {
	Sign([]byte) []byte
	Verify([]byte) ([]byte, bool)
}

type TimeSigner interface {
	Sign([]byte) []byte
	Verify([]byte, time.Duration) ([]byte, bool)
}

type Base64Signer struct {
	h   hash.Hash
	Sep []byte
}

func NewBase64Signer(h hash.Hash) *Base64Signer {
	return &Base64Signer{
		h:   h,
		Sep: []byte{'.'},
	}
}

func (s *Base64Signer) base64Encode(b []byte) []byte {
	dst := make([]byte, base64.URLEncoding.EncodedLen(len(b)))
	base64.URLEncoding.Encode(dst, b)
	for i := len(dst) - 1; i > 0; i-- {
		if dst[i] == '=' {
			dst = dst[:i]
		}
	}
	return dst
}

func (s *Base64Signer) base64Decode(b []byte) ([]byte, error) {
	for i := 0; i < len(b)%4; i++ {
		b = append(b, '=')
	}

	dst := make([]byte, base64.URLEncoding.DecodedLen(len(b)))
	n, err := base64.URLEncoding.Decode(dst, b)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func (s *Base64Signer) signature(b []byte) []byte {
	s.h.Reset()
	s.h.Write(b)
	return s.base64Encode(s.h.Sum(nil))
}

func (s *Base64Signer) Sign(msg []byte) []byte {
	signature := s.signature(msg)
	msg = append(msg, s.Sep...)
	msg = append(msg, signature...)
	return msg
}

func (s Base64Signer) Verify(b []byte) ([]byte, bool) {
	parts := splitRight(b, s.Sep)
	if len(parts) != 2 {
		return nil, false
	}
	msg, signature := parts[0], parts[1]
	signature2 := s.signature(msg)
	if subtle.ConstantTimeCompare(signature, signature2) != 1 {
		return nil, false
	}
	return msg, true
}

type Base64TimeSigner struct {
	*Base64Signer
}

func NewBase64TimeSigner(h hash.Hash) *Base64TimeSigner {
	return &Base64TimeSigner{
		Base64Signer: NewBase64Signer(h),
	}
}

func (s *Base64TimeSigner) encodeTime(unixTime int64) []byte {
	unixTime -= itsDangerousEpoch
	b := make([]byte, 0, 8)
	for i := uint(0); unixTime > 0; i++ {
		unixTime >>= i * 8
		b = append(b, byte(unixTime))
	}
	return s.base64Encode(b)
}

func (s *Base64TimeSigner) decodeTime(b []byte) int64 {
	b, err := s.base64Decode(b)
	if err != nil {
		return 0
	}

	var unixTime int64
	for i, v := range b {
		pos := len(b) - 1 - i
		unixTime |= int64(v) << (uint(pos) * 8)
	}
	unixTime += itsDangerousEpoch
	return unixTime
}

func (s *Base64TimeSigner) Sign(msg []byte) []byte {
	now := time.Now().Unix()
	msg = append(msg, s.Sep...)
	msg = append(msg, s.encodeTime(now)...)
	return s.Base64Signer.Sign(msg)
}

func (s *Base64TimeSigner) Verify(b []byte, dur time.Duration) ([]byte, bool) {
	msg, ok := s.Base64Signer.Verify(b)
	if !ok {
		return nil, false
	}

	parts := splitRight(msg, s.Sep)
	if len(parts) != 2 {
		return nil, false
	}
	msg, timeBytes := parts[0], parts[1]
	unixTime := s.decodeTime(timeBytes)
	if time.Since(time.Unix(unixTime, 0)) > dur {
		return nil, false
	}

	return msg, true
}

func splitRight(b []byte, sep []byte) [][]byte {
	ind := bytes.LastIndex(b, sep)
	if ind <= -1 {
		return [][]byte{b}
	}
	return [][]byte{b[:ind], b[ind+1:]}
}

type TimeSignatory interface {
	TimeSigner
}

type timesignatory struct {
	key    []byte
	salt   []byte
	hasher func() hash.Hash
	*Base64TimeSigner
}

func (t *timesignatory) secret() []byte {
	var b bytes.Buffer
	b.Write(t.key)
	b.Write(t.salt)
	return b.Bytes()
}

func NewTimeSignatory(key string, salt string, hasher func() hash.Hash) TimeSignatory {
	ts := &timesignatory{
		key:    []byte(key),
		salt:   []byte(salt),
		hasher: hasher,
	}
	h := hmac.New(ts.hasher, ts.secret())
	ts.Base64TimeSigner = NewBase64TimeSigner(h)
	return ts
}
