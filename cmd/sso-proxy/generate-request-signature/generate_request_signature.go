package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/proxy"
)

// Name of the header used to transmit the signature computed for the request.
var signatureHeader = "Sso-Signature"
var signingKeyHeader = "kid"

func main() {
	logger := logging.NewLogEntry()
	var requestSigner *proxy.RequestSigner

	config, err := proxy.LoadConfig()
	if err != nil {
		logger.Error(err, "error loading in config from env vars")
		os.Exit(1)
	}

	urlPtr := flag.String("url", "", "URL of request to sign")
	methodPtr := flag.String("method", "GET", "Method of request to sign")
	bodyPtr := flag.String("body", "", "Body of request to sign")

	err = config.Validate()
	if err != nil {
		logger.Error(err, "error validating config")
		os.Exit(1)
	}

	requestSigner, err = proxy.NewRequestSigner(config.RequestSignerConfig.Key)
	if err != nil {
		logger.Error(err, "error creating request signer")
		os.Exit(1)
	}

	flag.Parse()
	args := flag.Args()

	requestBody := *strings.NewReader(*bodyPtr)

	req, err := http.NewRequest(*methodPtr, *urlPtr, &requestBody)
	if err != nil {
		logger.Error(err, "error creating request")
		os.Exit(1)
	}

	for _, h := range args {
		hKv := strings.Split(h, ":")
		req.Header.Set(hKv[0], hKv[1])
	}

	err = requestSigner.Sign(req)
	if err != nil {
		logger.Error(err, "error signing request")
		os.Exit(1)
	}

	signature := req.Header.Get(signatureHeader)
	keyHeader := req.Header.Get(signingKeyHeader)

	fmt.Printf("URL: %v\n", *urlPtr)
	fmt.Printf("method: %v\n", *methodPtr)
	fmt.Printf("body: %v\n", *bodyPtr)
	fmt.Printf("headers: %v\n", req.Header)
	fmt.Println("==================================================================")

	fmt.Printf("signature: %v\n", signature)
	fmt.Printf("keyHeader: %v\n", keyHeader)
}
