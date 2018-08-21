package aead

import (
	"reflect"
	"testing"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")
	plaintext := []byte("my plain text value")

	c, err := NewMiscreantCipher([]byte(key))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if reflect.DeepEqual(plaintext, ciphertext) {
		t.Fatalf("plaintext is not encrypted plaintext:%v ciphertext:%x", plaintext, ciphertext)
	}

	got, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("unexpected err decrypting: %v", err)
	}

	if !reflect.DeepEqual(got, plaintext) {
		t.Logf(" got: %v", got)
		t.Logf("want: %v", plaintext)
		t.Fatal("got unexpected decrypted value")
	}
}

func TestMarshalAndUnmarshalStruct(t *testing.T) {
	key := []byte("0123456789abcdefghijklmnopqrstuv")

	c, err := NewMiscreantCipher([]byte(key))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	type TC struct {
		Field string `json:"field"`
	}

	tc := &TC{
		Field: "my plain text value",
	}

	value1, err := c.Marshal(tc)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	value2, err := c.Marshal(tc)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}

	if value1 == value2 {
		t.Fatalf("expected marshaled values to not be equal %v != %v", value1, value2)
	}

	got1 := &TC{}
	err = c.Unmarshal(value1, got1)
	if err != nil {
		t.Fatalf("unexpected err unmarshalling struct: %v", err)
	}

	if !reflect.DeepEqual(got1, tc) {
		t.Logf("want: %#v", tc)
		t.Logf(" got: %#v", got1)
		t.Fatalf("expected structs to be equal")
	}

	got2 := &TC{}
	err = c.Unmarshal(value2, got2)
	if err != nil {
		t.Fatalf("unexpected err unmarshalling struct: %v", err)
	}

	if !reflect.DeepEqual(got1, got2) {
		t.Logf("got2: %#v", got2)
		t.Logf("got1: %#v", got1)
		t.Fatalf("expected structs to be equal")
	}
}
