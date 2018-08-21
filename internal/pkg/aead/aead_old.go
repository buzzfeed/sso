package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
)

const nonceSize = 12

// OldCipher provides methods to encrypt and decrypt values.
// Using an AEAD is a cipher providing authenticated encryption with associated data.
// For a description of the methodology, see https://en.wikipedia.org/wiki/Authenticated_encryption
type OldCipher struct {
	cipher.AEAD
}

// NewOldCipher returns a new AES Cipher for encrypting values
func NewOldCipher(secret []byte) (*OldCipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	return &OldCipher{
		AEAD: aesgcm,
	}, nil
}

// Encrypt a value using AES GCM
func (c *OldCipher) Encrypt(plaintext []byte) ([]byte, error) {
	nonce, err := Nonce(nonceSize)
	if err != nil {
		return nil, err
	}

	ciphertext := c.AEAD.Seal(nil, nonce, plaintext, nil)

	// we return the nonce as part of the returned value
	joined := append(ciphertext[:], nonce[:]...)
	return joined, nil
}

// Decrypt a value using AES GCM
func (c *OldCipher) Decrypt(joined []byte) ([]byte, error) {
	// grab out the nonce
	pivot := len(joined) - nonceSize
	ciphertext := joined[:pivot]
	nonce := joined[pivot:]

	plaintext, err := c.AEAD.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Marshal marshals the interface state as JSON, encrypts the JSON using the cipher
// and base64 encodes teh binary value as a string and returns the result
func (c *OldCipher) Marshal(s interface{}) (string, error) {
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
	encoded := base64.URLEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

// Unmarshal takes the marshaled string, base64-decodes into a byte slice, decrypts the
// byte slice the pased cipher, and unmarshals the resulting JSON into the struct pointer passed
func (c *OldCipher) Unmarshal(value string, s interface{}) error {
	// convert base64 string value to bytes
	ciphertext, err := base64.URLEncoding.DecodeString(value)
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

// Nonce returns a one time use random number
func Nonce(length int) ([]byte, error) {
	nonce := make([]byte, nonceSize)

	_, err := io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return nonce, nil
}
