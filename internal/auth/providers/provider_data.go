package providers

import (
	"net/url"
	"time"
)

// ProviderData holds the fields associated with providers
// necessary to implement the Provider interface.
type ProviderData struct {
	ProviderName       string
	ClientID           string
	ClientSecret       string
	SignInURL          *url.URL
	RedeemURL          *url.URL
	RevokeURL          *url.URL
	ProfileURL         *url.URL
	ValidateURL        *url.URL
	Scope              string
	ApprovalPrompt     string
	SessionLifetimeTTL time.Duration
}

// Data returns a ProviderData.
func (p *ProviderData) Data() *ProviderData { return p }
