package payloads

import (
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

const secret = "0123456789abcdefghijklmnopqrstuv"
const altSecret = "0000000000abcdefghijklmnopqrstuv"
const token = "my access token"

func TestPayloadRoundTrip(t *testing.T) {
	c, err := NewCipher([]byte(secret))
	testutil.Equal(t, nil, err)

	payload := New("name", token, "salt", time.Now(), c)
	encrypted, err := Encrypt(payload)
	testutil.Equal(t, nil, err)

	payload, err = Decrypt("name", encrypted, "salt", (time.Duration(1) * time.Hour), c)
	testutil.Equal(t, nil, err)
	testutil.Equal(t, token, payload.Value)
}

func TestValidation(t *testing.T) {
	cipher, err := NewCipher([]byte(secret))
	badCipher, err := NewCipher([]byte(altSecret))
	testutil.Equal(t, nil, err)

	created := time.Now().Add(time.Duration(2) * time.Hour)
	payload := New("name", token, "salt", created, cipher)
	encrypted, err := Encrypt(payload)
	testutil.Equal(t, nil, err)

	longExpiration := time.Duration(3) * time.Hour
	shortExpiration := time.Duration(1) * time.Hour

	payload, err = Decrypt("wrongname", encrypted, "salt", longExpiration, cipher)
	testutil.Equal(t, "invalid signature", err.Error())

	payload, err = Decrypt("name", encrypted, "wrongsalt", longExpiration, cipher)
	testutil.Equal(t, "invalid signature", err.Error())

	payload, err = Decrypt("name", encrypted, "salt", longExpiration, badCipher)
	testutil.Equal(t, "incorrect format", err.Error())

	payload, err = Decrypt("name", encrypted, "salt", shortExpiration, cipher)
	testutil.Equal(t, "payload expired", err.Error())

	testCases := []struct {
		Blob  string
		Error string
	}{
		{
			Blob:  "wrong|number|of|tokens",
			Error: "incorrect format",
		},
		{
			Blob:  "value not base64|0|Zm9vYmFy",
			Error: "could not decode value",
		},
		{
			Blob:  "Zm9vYmFy|invalid timestamp|Zm9vYmFy",
			Error: "could not parse timestamp",
		},
		{
			Blob:  "Zm9vYmFy|0|signature not base64",
			Error: "could not decode signature",
		},
		{
			Blob:  "Zm9vYmFy|0|Zm9vYmFy",
			Error: "invalid signature",
		},
	}

	for _, tc := range testCases {
		encrypted, err = cipher.Encrypt(tc.Blob)
		testutil.Equal(t, nil, err)
		payload, err = Decrypt("name", encrypted, "salt", longExpiration, cipher)
		testutil.Equal(t, tc.Error, err.Error())
	}
}
