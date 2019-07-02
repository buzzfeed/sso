# sso

> See our launch [blog post](https://tech.buzzfeed.com/unleashing-the-a6a1a5da39d6) for more information!

[![CircleCI](https://circleci.com/gh/buzzfeed/sso.svg?style=svg)](https://circleci.com/gh/buzzfeed/sso)
[![MIT license](http://img.shields.io/badge/license-MIT-brightgreen.svg)](http://opensource.org/licenses/MIT)
[![Docker Automated build](https://img.shields.io/docker/automated/buzzfeed/sso.svg)](https://hub.docker.com/r/buzzfeed/sso/)
[![codecov.io](https://codecov.io/github/buzzfeed/sso/coverage.svg?branch=master)](https://codecov.io/github/buzzfeed/sso?branch=master)


<img src="https://user-images.githubusercontent.com/10510566/44476420-a64e5980-a605-11e8-8ad9-2820109deb75.png" width="128px">

> Please take the [SSO Community Survey][sso_survey] to let us know how we're doing, and to help us plan our roadmap!

----

**sso** — lovingly known as *the S.S. Octopus* or *octoboi* — is the
authentication and authorization system BuzzFeed developed to provide a secure,
single sign-on experience for access to the many internal web apps used by our
employees.

It depends on Google as its authoritative OAuth2 provider, and authenticates
users against a specific email domain. Further authorization based on Google
Group membership can be required on a per-upstream basis.

The main idea behind **sso** is a "double OAuth2" flow, where `sso-auth` is the
OAuth2 provider for `sso-proxy` and Google is the OAuth2 provider for `sso-auth`.

[sso](https://github.com/buzzfeed/sso) is built on top of Bitly’s open source [oauth2_proxy](https://github.com/bitly/oauth2_proxy)

In a nutshell:

- If a user visits an `sso-proxy`-protected service (`foo.sso.example.com`) and does not have a session cookie, they are redirected to `sso-auth` (`sso-auth.example.com`).
   - If the user **does not** have a session cookie for `sso-auth`,
     they are prompted to log in via the usual Google OAuth2 flow, and then
     redirected back to `sso-proxy` where they will now be logged in (to
     `foo.sso.example.com`)
   - If the user *does* have a session cookie for `sso-auth` (e.g. they
     have already logged into `bar.sso.example.com`), they are
     transparently redirected back to `proxy` where they will be logged in,
     without needing to go through the Google OAuth2 flow
- `sso-proxy` transparently re-validates & refreshes the user's session with `sso-auth`

## Installation

- [Prebuilt binary releases](https://github.com/buzzfeed/sso/releases)
- [Docker][docker_hub]
- `go get github.com/buzzfeed/sso/cmd/...`

## Quickstart

Follow our [Quickstart guide](docs/quickstart.md) to spin up a local deployment
of **sso** to get a feel for how it works!

## Code of Conduct

Help us keep **sso** open and inclusive. Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributing

Contributions to **sso** are welcome! Please follow our [contribution guideline](CONTRIBUTING.md).

### Issues

Please file any issues you find in our [issue tracker](https://github.com/buzzfeed/sso/issues).

### Security Vulns

If you come across any security vulnerabilities with the **sso** repo or software, please email security@buzzfeed.com. In your email, please request access to our [bug bounty program](https://hackerone.com/buzzfeed) so we can compensate you for any valid issues reported.

## Maintainers

**sso** is actively maintained by the BuzzFeed Infrastructure teams.

## Notable forks

 - [pomerium](https://github.com/pomerium/pomerium) an identity-access proxy, inspired by BeyondCorp.

[docker_hub]: https://hub.docker.com/r/buzzfeed/sso/
[sso_survey]: https://docs.google.com/forms/d/e/1FAIpQLSeRjf66ZSpMkSASMbYebx6QvECYRj9nUevOhUF2huw53sE6_g/viewform
