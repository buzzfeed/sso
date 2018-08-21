package sessions

import (
	"reflect"
	"testing"
	"time"

	"github.com/buzzfeed/sso/internal/pkg/aead"
)

func TestSessionStateSerialization(t *testing.T) {
	secret := "0123456789abcdefghijklmnopqrstuv"

	c, err := aead.NewMiscreantCipher([]byte(secret))
	if err != nil {
		t.Fatalf("expected to be able to create cipher: %v", err)
	}

	want := &SessionState{
		AccessToken:  "token1234",
		RefreshToken: "refresh4321",

		LifetimeDeadline: time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
		RefreshDeadline:  time.Now().Add(1 * time.Hour).Truncate(time.Second).UTC(),
		ValidDeadline:    time.Now().Add(1 * time.Minute).Truncate(time.Second).UTC(),

		Email: "user@domain.com",
		User:  "user",
	}

	ciphertext, err := MarshalSession(want, c)
	if err != nil {
		t.Fatalf("expected to be encode session: %v", err)
	}

	got, err := UnmarshalSession(ciphertext, c)
	if err != nil {
		t.Fatalf("expected to be decode session: %v", err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Logf("want: %#v", want)
		t.Logf(" got: %#v", got)
		t.Errorf("encoding and decoding session resulted in unexpected output")
	}
}

func TestSessionStateExpirations(t *testing.T) {
	session := &SessionState{
		AccessToken:  "token1234",
		RefreshToken: "refresh4321",

		LifetimeDeadline: time.Now().Add(-1 * time.Hour),
		RefreshDeadline:  time.Now().Add(-1 * time.Hour),
		ValidDeadline:    time.Now().Add(-1 * time.Minute),

		Email: "user@domain.com",
		User:  "user",
	}

	if !session.LifetimePeriodExpired() {
		t.Errorf("expcted lifetime period to be expired")
	}

	if !session.RefreshPeriodExpired() {
		t.Errorf("expcted lifetime period to be expired")
	}

	if !session.ValidationPeriodExpired() {
		t.Errorf("expcted lifetime period to be expired")
	}
}
