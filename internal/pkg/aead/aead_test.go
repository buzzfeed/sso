package aead

import (
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	plaintext := []byte("my plain text value")

	key := GenerateKey()
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
	key := GenerateKey()

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

// TestCipherDataRace exercises a simple concurrency test for the MicscreantCipher.
// In https://github.com/buzzfeed/sso/pull/75 we investigated why, on random occasion,
// unmarshalling session states would fail, triggering users to get kicked out of
// authenticated states. We narrowed our investigation to a data race we uncovered
// from our misuse of the underlying miscreant library which makes no attempt
// at thread-safety.
//
// In https://github.com/buzzfeed/sso/pull/77 we added this test to exercise the
// data race condition and resolved said race by introducing a simple mutex.
func TestCipherDataRace(t *testing.T) {
	miscreantCipher, err := NewMiscreantCipher(GenerateKey())
	if err != nil {
		t.Fatalf("unexpected generating cipher err: %v", err)
	}

	type TC struct {
		Field string `json:"field"`
	}

	// Create a channel to collect errors from goroutines
	errCh := make(chan error, 100)

	wg := &sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(c *MiscreantCipher, wg *sync.WaitGroup, errCh chan<- error) {
			defer wg.Done()
			b := make([]byte, 32)
			_, err := rand.Read(b)
			if err != nil {
				errCh <- fmt.Errorf("unexpected error reading random bytes: %v", err)
				return
			}

			sha := fmt.Sprintf("%x", sha1.New().Sum(b))
			tc := &TC{
				Field: sha,
			}

			value1, err := c.Marshal(tc)
			if err != nil {
				errCh <- fmt.Errorf("unexpected err: %v", err)
				return
			}

			value2, err := c.Marshal(tc)
			if err != nil {
				errCh <- fmt.Errorf("unexpected err: %v", err)
				return
			}

			if value1 == value2 {
				errCh <- fmt.Errorf("expected marshaled values to not be equal %v != %v", value1, value2)
				return
			}

			got1 := &TC{}
			err = c.Unmarshal(value1, got1)
			if err != nil {
				errCh <- fmt.Errorf("unexpected err unmarshalling struct: %v", err)
				return
			}

			if !reflect.DeepEqual(got1, tc) {
				errCh <- fmt.Errorf("expected structs to be equal: want %#v, got %#v", tc, got1)
				return
			}

			got2 := &TC{}
			err = c.Unmarshal(value2, got2)
			if err != nil {
				errCh <- fmt.Errorf("unexpected err unmarshalling struct: %v", err)
				return
			}

			if !reflect.DeepEqual(got1, got2) {
				errCh <- fmt.Errorf("expected structs to be equal: got1 %#v, got2 %#v", got1, got2)
				return
			}

		}(miscreantCipher, wg, errCh)
	}

	go func() {
		wg.Wait()
		close(errCh) // Close the channel after all goroutines have finished
	}()

	// Collect and handle errors from the channel
	for err := range errCh {
		t.Errorf("Test failed: %v", err)
	}
}
