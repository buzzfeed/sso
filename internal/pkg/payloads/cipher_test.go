package payloads

import (
	"encoding/base64"
	"testing"

	"github.com/buzzfeed/sso/internal/pkg/testutil"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewCipher([]byte(secret))
	testutil.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	testutil.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	testutil.Equal(t, nil, err)

	testutil.NotEqual(t, token, encoded)
	testutil.Equal(t, token, decoded)
}

func TestEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secretB64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secretB64)
	c, err := NewCipher([]byte(secret))
	testutil.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	testutil.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	testutil.Equal(t, nil, err)

	testutil.NotEqual(t, token, encoded)
	testutil.Equal(t, token, decoded)
}
