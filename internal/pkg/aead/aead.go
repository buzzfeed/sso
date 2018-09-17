package aead

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"

	miscreant "github.com/miscreant/miscreant/go"
)

const miscreantNonceSize = 16

var algorithmType = "AES-CMAC-SIV"

var (
	// ErrInvalidValue is an error for an invalid value
	ErrInvalidValue = errors.New("invalid value")
)

// Cipher provides methods to encrypt and decrypt values.
type Cipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	Marshal(interface{}) (string, error)
	Unmarshal(string, interface{}) error
}

// MiscreantCipher provides methods to encrypt and decrypt values.
// Using an AEAD is a cipher providing authenticated encryption with associated data.
// For a description of the methodology, see https://en.wikipedia.org/wiki/Authenticated_encryption
type MiscreantCipher struct {
	aead cipher.AEAD
}

// NewMiscreantCipher returns a new AES Cipher for encrypting values
func NewMiscreantCipher(secret []byte) (*MiscreantCipher, error) {
	aead, err := miscreant.NewAEAD(algorithmType, secret, miscreantNonceSize)
	if err != nil {
		return nil, err
	}
	return &MiscreantCipher{
		aead: aead,
	}, nil
}

// GenerateKey wraps miscreant's GenerateKey function
func GenerateKey() []byte {
	return miscreant.GenerateKey(32)
}

// Encrypt a value using AES GCM
func (c *MiscreantCipher) Encrypt(plaintext []byte) (joined []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = ErrInvalidValue
		}
	}()
	nonce := miscreant.GenerateNonce(c.aead)
	ciphertext := c.aead.Seal(nil, nonce, plaintext, nil)

	// we return the nonce as part of the returned value
	joined = append(ciphertext[:], nonce[:]...)
	return joined, nil
}

// Decrypt a value using AES GCM
func (c *MiscreantCipher) Decrypt(joined []byte) ([]byte, error) {
	if len(joined) <= miscreantNonceSize {
		return nil, ErrInvalidValue
	}
	// grab out the nonce
	pivot := len(joined) - miscreantNonceSize
	ciphertext := joined[:pivot]
	nonce := joined[pivot:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Marshal marshals the interface state as JSON, encrypts the JSON using the cipher
// and base64 encodes the binary value as a string and returns the result
func (c *MiscreantCipher) Marshal(s interface{}) (string, error) {
	// encode json value
	plaintext, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	// encrypt the JSON
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		return "", err
	}

	// base64-encode the result
	encoded := base64.RawURLEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

// Unmarshal takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice the pased cipher, and unmarshals the resulting JSON into the struct pointer passed
func (c *MiscreantCipher) Unmarshal(value string, s interface{}) error {
	// convert base64 string value to bytes
	ciphertext, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	// decrypt the bytes
	plaintext, err := c.Decrypt(ciphertext)
	if err != nil {
		return err
	}

	// unmarshal bytes
	err = json.Unmarshal(plaintext, s)
	if err != nil {
		return err
	}

	return nil
}
