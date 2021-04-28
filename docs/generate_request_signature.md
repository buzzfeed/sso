## sso_proxy/generate-request-signature
`sso-generate-request-signature` is a command-line tool that is provided alongside `sso_proxy` to facilitate upstream testing of SSO's proxied request signatures, or of libraries that attempt to validate signatures. Note that running `sso-generate-request-signature` requires some of the same configuration to be in place as running `sso-proxy` would, i.e. a `REQUESTSIGNER_KEY` environment variable. Assuming that exists, the tool can be run with three optional flags, followed by as many request headers as desired in `<name>:<value>` format:

- `-url`: the path of the URL of the request to calculate the signature on (default: "")
- `-method`: the method of the request (default: "GET") (note: the method is not used in the signature calculation)
- `-body`: for PUT or POST requests, a string representing the body of the request to calculate a signature on (default: "")

### examples
`sso-generate-request-signature -url "/foo" -method "POST" -body "{}" x-header-1:bar x-header-2:baz`

`sso-generate-request-signature -url "/bar"`
