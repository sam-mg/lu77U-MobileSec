# OAuth 2.0 and OpenID Connect in an Android App

A login flow is a chain of hand-offs: the app sends the user to an identity
provider, the provider sends something back to the app, and the app trades it
for tokens. Every hand-off is a place where another app, a web page or a
proxy can step in. Read the flow end to end before judging any single part.

## Find the flow

Search the app's own code, not the libraries it bundles:

- `authorize`, `response_type`, `redirect_uri`, `code_challenge`, `client_id`,
  `/token`, `grant_type`, `id_token`, `nonce`, `state`
- AppAuth (`AuthorizationRequest.Builder`, `AuthorizationService`), Google/
  Facebook/Microsoft sign-in SDKs, Auth0, Okta, Firebase Auth
- The redirect URI's scheme in the manifest: an intent filter on the activity
  that receives the callback (AppAuth's `RedirectUriReceiverActivity` or the
  app's own)
- In React Native, the same strings in `app_modules/`; in Flutter, in the
  object pool and the app's Dart

## What to check, in order of impact

1. **Grant type.** A native app should use the authorization code grant with
   PKCE. `response_type=token` (implicit) puts the access token in the redirect
   URL. `grant_type=password` sends the user's password through the app and
   skips the provider's own protections. Both are findings on their own.
2. **PKCE.** Look for `code_challenge` and `code_challenge_method=S256`. A
   missing challenge, or `plain`, means a second app that catches the redirect
   can redeem the code. The verifier must be random (`SecureRandom`, 43-128
   characters) and new for every login.
3. **Redirect URI.** A custom scheme (`myapp://callback`) can be registered by
   any other app, so a code sent there can be intercepted; PKCE is what makes
   that harmless. A verified App Link (`https` with `android:autoVerify="true"`)
   cannot be claimed by another app. Custom scheme without PKCE is the
   high-impact combination.
4. **Where the login page runs.** The provider's page belongs in the system
   browser or a Custom Tab. In an embedded WebView the app can read every
   keystroke and cookie, and the user cannot tell the page is real - this is a
   finding even when the app is honest, because it trains users to type
   passwords into apps.
5. **state and nonce.** `state` must be random, stored before the redirect and
   compared when the callback arrives; without it, an attacker can complete a
   login with their own code (login CSRF). With OpenID Connect, the `nonce`
   sent must be the one in the returned `id_token`.
6. **The callback handler.** The activity receiving the redirect is exported by
   necessity. Read what it does with `code`, `state` or a bare token from the
   Intent: if it accepts them without matching a pending request, any app or
   link can push a session into it.
7. **Client secret in the app.** `client_secret` in code, resources or a config
   file is not secret. A native app is a public client; a provider that requires
   a secret from it is misconfigured. Report where the value is and what the
   provider says it authorises.
8. **Token handling.** Where the access and refresh tokens are stored (see
   `storage_crypto_review`), whether they appear in logs or URLs, and whether
   logout revokes them or only deletes the local copy.
9. **ID token checks done in the app.** Signature, `iss`, `aud`, `exp` and the
   `alg` header (reject `none`). If the app decodes an ID token and trusts its
   claims to decide who the user is, without the server verifying it, the
   claims are the attacker's to write.
10. **Step-up done on the client.** A biometric prompt or PIN screen that gates
    a token, with nothing on the server checking it, is a client-side check:
    see `finding_quality` on what is not a mitigation.

## Who the attacker is

- Code interception through a shared custom scheme: **another app**.
- Login CSRF through an unbound callback: **remote** when a web page can fire
  the redirect URL, otherwise another app.
- Token in a URL or a log: whoever reads that channel - a proxy, a log reader,
  another app reading a shared log on an old Android version.
- Embedded-WebView login: the app itself, plus anyone who can inject into the
  WebView.

## Writing it up

Cite the authorization request (where the parameters are set), the redirect
intent filter, and the callback handler. Say which of the checks above fail
and what an attacker obtains: a working access token, a session bound to the
attacker's account, the user's password. A missing control that another
control covers - a custom scheme with S256 PKCE, say - is a note, not a
vulnerability.
