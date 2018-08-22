# Overview

# SSO
> Single-Sign-On
> SSO is a system that providers a single sign-on experience for the web services that are behind it


SSO is used to provide single-sign-on authentication and authorization for internal web
applications behind it by ensuring that only people in a specific email domain (and optionally
users in specific Google Groups) can access them. It consists of two processes -
`sso_auth` and `sso_proxy`. 

The main idea of SSO is a "double OAuth2" flow, where `sso_auth` is the
OAuth2 provider for `sso_proxy`, and Google, or another third-party provider,
 is the OAuth2 provider for `sso_auth`.

In a nutshell:

1. If a user visits a `sso_proxy`-protected service
   (`foo.sso.example.com`) and does not have a session cookie, they are
   redirected to `sso_auth` (`sso-auth.example.com`)
   - If the user **does not** have a session cookie for `sso_auth`,
     they are prompted to log in via the usual Google OAuth2 flow, and then
     redirected back to `sso_proxy` where they will now be logged in (to
     `foo.sso.example.com`)
   - If the user *does* have a session cookie for `sso_auth` (e.g. they
     have already logged into `bar.sso.example.com`), they are
     transparently redirected back to `sso_proxy` where they will be logged in,
     without needing to go through the Google OAuth2 flow
2. `sso_proxy` transparently re-validates & refreshes the user's session with
   `sso_auth`
3. After 15 days, all sessions are expired and `sso_proxy` will redirect the
   user to `sso_auth` to go through the Google OAuth2 flow once, after
   which they will again have access to all SSO-protected services

