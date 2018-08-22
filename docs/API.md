# API

## User-facing endpoints

### GET /sign_in
Serves the sign in button.

|Query Parameters| |
|:---|:---|
|`client_id`|The unique client id for the SSO proxy|
|`redirect_uri`|The redirect URI to return to when the authentication with Google is complete.|
|`redirect_sig`|The signature for the redirect URI. See **Redirect Validation** below for a description on how the redirect URI is signed.|

### GET /sign_out
Serves the sign out button. This page requires a valid redirect URI, so you can get here via the proxy: `{{service}}.sso.example.com/oauth2/sign_out`

|Query Parameters| |
|:---|:---|
|`redirect_uri`|A redirect URI pointing to the proxy to return to when de-authentication is complete.|
|`redirect_sig`|The signature for the redirect URI. See **Redirect Validation** below for a description on how the redirect URI is signed.|

### GET /static/...
This serves static CSS and image files for the sign in, sign out, and error
pages for both `sso_auth` and `sso_proxy`.

## Endpoints to authenticate a user

### POST /start
This is the entrance to the OAuth flow, which is started via the HTML form
`POST` from "the button".

|Parameters| |
|:---|:---|
|`redirect_uri`|The redirect URI back to the _authenticator_. This URI contains query parameters, `redirect_uri` (AKA the nested redirect) and `redirect_sig`, which redirect back to the proxy and sign the nested redirect, respectively.|

### GET /oauth2/callback
Once the user has authenticated with the provider, they are redirected to
this endpoint, which sets the Authenticator Cookie and then redirects
them back to Proxy.

### POST /sign_out
Revokes the token with the provider

|Parameters| |
|:---|:---|
|`redirect_uri`|A redirect URI pointing to the proxy to return to when de-authentication is complete.|
|`redirect_sig`|The signature for the redirect URI. See **Redirect Validation** below for a description on how the redirect URI is signed.|

## Endpoints to function as an OAuth Provider

### GET /profile
This method returns the Google group membership given an email address. The
proxy uses this list of groups to determine whether a user has access to the
upstream service.

|Parameters| |
|:---|:---|
|`email`|The user's email|
|`client_id`|The unique client id for the SSO proxy|
|`X-Client-Secret` header|The proxy's client secret. This is a request being made directly from `sso_proxy` to `sso_auth`|

|Response| |
|:---|:---|
|`email`|The user's email address|
|`groups`|A list of all Google groups memberships for the user. `sso_proxy` is responsible for validating that the user is a member of the correct group for the upstream.|

### GET /validate
Returns OK if an access token is valid.

|Parameters| |
|:---|:---|
|`client_id`|The unique client id for the SSO proxy|
|`X-Access-Token` header|The access token from Google|
|`X-Client-Secret` header|The proxy's client secret. This is a request being made directly from `sso_proxy` to `sso_auth`|

### POST /redeem
Redeem an access code for an access token and refresh token.

|Parameters| |
|:---|:---|
|`code`|An encrypted payload which contains the access token.|
|`client_id`|The unique client id for the SSO proxy|
|`client_secret`|The proxy's client secret. This is a request being made directly from `sso_proxy` to `sso_auth`|

|Response| |
|:---|:---|
|`access_token`|The access token from Google|
|`refresh_token`|The refresh token from Google|
|`expires_in`|The expiration timestamp of `access_token`|
|`email`|The user's email address|

### POST /refresh
Refresh the access token using the refresh token.

|Parameters| |
|:---|:---|
|`refresh_token`|The refresh token from Google.|
|`client_id`|The unique client id for the SSO proxy|
|`client_secret`|The proxy's client secret. This is a request being made directly from `sso_proxy` to `sso_auth`|

|Response| |
|:---|:---|
|`access_token`|The access token from Google|
|`expires_in`|The expiration timestamp of `access_token`|
