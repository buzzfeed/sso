# SSO

[![CircleCI](https://circleci.com/gh/buzzfeed/sso.svg?style=svg)](https://circleci.com/gh/buzzfeed/sso)
[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)

<img src="docs/img/logo.png" width="128px">

----

BuzzFeed's SSO is our single sign-on experience for our internal web services, lovingly known as the *S.S. Octopus* (octoboi) by our team. In addition to the source code, we publish an official [Docker image][docker_hub].

SSO is used to provide single-sign-on authentication and authorization for internal web applications behind it by ensuring that only people in a specific email domain (and optionally users in specific Google Groups) can access them. It consists of two processes - `auth` and `proxy`.

The main idea of COP is a "double OAuth2" flow, where `auth` is the OAuth2 provider for `proxy`, and Google or another third-party provider, is the OAuth2 provider for `auth`.

In a nutshell:

1. If a user visits a `proxy`-protected service (`foo.sso.example.com`) and does not have a session cookie, they are redirected to `auth` (`sso-auth.example.com`).
   - If the user **does not** have a session cookie for `auth`,
     they are prompted to log in via the usual Google OAuth2 flow, and then
     redirected back to `proxy` where they will now be logged in (to
     `foo.sso.example.com`)
   - If the user *does* have a session cookie for `auth` (e.g. they
     have already logged into `bar.sso.example.com`), they are
     transparently redirected back to `proxy` where they will be logged in,
     without needing to go through the Google OAuth2 flow
2. `proxy` transparently re-validates & refreshes the user's session with `auth`
3. After 15 days, all sessions are expired and `proxy` will redirect the user to `auth` to go through the Google OAuth2 flow once, after which they will again have access to all COP-protected services.

## Code of Conduct

Help us keep SSO open and inclusive. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributing

Contributions to SSO are welcome! Please follow our [contribution guideline](CONTRIBUTING.md).

### Issues

Please file any issues you find in our [issue tracker](https://github.com/buzzfeed/sso/issues).

### Security Vulns

If you come across any security vulnerabilities with the SSO repo or software, please email security@buzzfeed.com. In your email, please request access to our [bug bounty program](https://hackerone.com/buzzfeed) so we can compensate you for any valid issues reported.

## Maintainers

SSO is actively maintained by the BuzzFeed Infrastructure teams.

[docker_hub]: https://hub.docker.com/r/buzzfeed/sso/