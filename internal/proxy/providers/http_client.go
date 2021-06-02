package providers

import (
	"net"
	"net/http"
	"time"
)

var httpClient = &http.Client{
	Timeout: time.Second * 5,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		Dial: (&net.Dialer{
			Timeout: 2 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 2 * time.Second,
	},
}
