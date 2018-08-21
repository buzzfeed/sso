# Architecture

## Redirect validation

Because the authentication process is a series of HTTP redirects, great care is
taken to ensure that redirect URLs are verified as non-malicious before respond
with an HTTP redirect.

We validate the root domain of the `redirect_uri` parameter, and we ensure that
it was not tampered with by validating the `redirect_sig`, an HMAC signature
which we construct using the `redirect_uri` and the proxy's client secret.

