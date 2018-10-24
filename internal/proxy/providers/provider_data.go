package providers

import (
	"net/url"
	"time"
)

// ProviderData holds the fields associated with providers
// necessary to implement the Provider interface.
type ProviderData struct {
	ProviderName      string
	ProviderURL       *url.URL
	ProxyProviderURL  *url.URL
	ClientID          string
	ClientSecret      string
	SignInURL         *url.URL
	SignOutURL        *url.URL
	RedeemURL         *url.URL
	ProxyRedeemURL    *url.URL
	RefreshURL        *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	Scope             string
	ApprovalPrompt    string

	SessionValidTTL    time.Duration
	SessionLifetimeTTL time.Duration
	GracePeriodTTL     time.Duration
}

// Data returns the ProviderData struct
func (p *ProviderData) Data() *ProviderData { return p }
