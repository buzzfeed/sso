package payloads

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

func formatTime(t time.Time) string {
	return fmt.Sprintf("%d", t.Unix())
}

func parseTime(t string) (time.Time, error) {
	ts, err := strconv.Atoi(t)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(int64(ts), 0), nil
}

// separates the encoded blob (in the format "value|timestamp|signature") into its component parts
func parseBlob(blob string) (value string, timestamp time.Time, signature []byte, err error) {
	// split blob and verify number of elements
	parts := strings.Split(blob, "|")
	if len(parts) != 3 {
		err = errors.New("incorrect format")
		return
	}

	// decode the original value from its base64 representation
	bytes, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		err = errors.New("could not decode value")
		return
	}
	value = string(bytes)

	// parse the timestamp to time.Time
	timestamp, err = parseTime(parts[1])
	if err != nil {
		err = errors.New("could not parse timestamp")
		return
	}

	// decode the base64 signature into []byte
	signature, err = base64.URLEncoding.DecodeString(parts[2])
	if err != nil {
		err = errors.New("could not decode signature")
		return
	}
	return
}

// Payload represents the information encoded in cookies.
// It contains a string Value, a timestamp Timestamp, a byte Signature, and a Cipher.
type Payload struct {
	Value     string
	Timestamp time.Time
	Signature []byte
	Cipher    *Cipher
}

// New returns a new payload.
func New(name, value, salt string, ts time.Time, cipher *Cipher) *Payload {
	h := hmac.New(sha256.New, []byte(salt))
	h.Write([]byte(name))
	h.Write([]byte(base64.URLEncoding.EncodeToString([]byte(value))))
	h.Write([]byte(formatTime(ts)))
	return &Payload{
		Value:     value,
		Timestamp: ts,
		Signature: h.Sum(nil),
		Cipher:    cipher,
	}
}

// Decrypt takes in a name, an encrypted value, a salt, expiration time and a cipher, and decrypts
// the value into a payload.
func Decrypt(name, encryptedValue, salt string, expiration time.Duration, cipher *Cipher) (*Payload, error) {
	blob, err := cipher.Decrypt(encryptedValue)
	if err != nil {
		return nil, errors.New("could not decrypt value for signed payload")
	}

	value, timestamp, signature, err := parseBlob(blob)
	if err != nil {
		return nil, err
	}

	p := New(name, value, salt, timestamp, cipher)
	return p, p.validate(signature, expiration)
}

// Encrypt takes in a payload and returns an encrypted value.
func Encrypt(p *Payload) (string, error) {
	encodedValue := base64.URLEncoding.EncodeToString([]byte(p.Value))
	sig := base64.URLEncoding.EncodeToString(p.Signature)
	blob := fmt.Sprintf("%s|%s|%s", encodedValue, formatTime(p.Timestamp), sig)
	encryptedValue, err := p.Cipher.Encrypt(blob)
	if err != nil {
		return "", err
	}
	return encryptedValue, nil
}

func (p *Payload) validate(sig []byte, expiration time.Duration) error {
	err := p.validateSignature(sig)
	if err != nil {
		return err
	}
	return p.validateExpiration(expiration)
}

func (p *Payload) validateSignature(sig []byte) error {
	if hmac.Equal(p.Signature, sig) {
		return nil
	}
	return errors.New("invalid signature")
}

func (p *Payload) validateExpiration(expiration time.Duration) error {
	if p.Timestamp.After(time.Now().Add(expiration*-1)) &&
		p.Timestamp.Before(time.Now().Add(time.Minute*5)) {
		return nil
	}
	return errors.New("payload expired")
}
