# Deep Links and the Clipboard - Untrusted Data Through a Side Door

Both carry data the user did not type and the app did not produce. A link can
come from any web page, message or QR code; the clipboard can be written by
any app the user ran. The question for both is the same: what does the app do
with the value, and does it act before a human confirms it?

## Deep links

### Find every entry

- Manifest intent filters with `VIEW` + `BROWSABLE` and a `data` scheme/host.
  A custom scheme is reachable from any web page and any app; an `https` link
  with `android:autoVerify="true"` is verified to the domain, but still
  reachable from the web.
- The code that reads it: `getIntent().getData()`, `Uri.getQueryParameter`,
  `getPathSegments`, `onNewIntent`. In React Native: `Linking.getInitialURL`,
  `Linking.addEventListener('url', ...)`, a navigation `linking` config. In
  Flutter: `app_links`/`uni_links` streams, `getInitialLink`, or a
  MethodChannel handler fed by `MainActivity.onNewIntent`.
- Deferred links from attribution SDKs (Branch, AppsFlyer, Adjust, Firebase
  Dynamic Links): their payload arrives later through the SDK callback, and is
  just as untrusted.

### What makes a link a vulnerability

1. **It performs an action, not just navigation.** A link that transfers money,
   changes settings, accepts an invitation, links an account or submits a form
   *on arrival* - with no confirmation screen and no nonce the attacker cannot
   know - is a one-tap attack from any web page. This is the most common
   high-impact deep-link finding and it is easy to miss: the handler often
   just pre-fills a screen and then calls the same submit method a button
   would.
2. **It opens a screen the session should guard.** A link straight into an
   account or payment screen that skips the PIN or biometric lock.
3. **A parameter reaches a sink.** A URL parameter loaded into a WebView
   (especially one with a JavaScript bridge: the link chooses the page that
   gets the bridge), passed to `startActivity`, used in a file path or SQL.
   Follow it with `taint_source_to_sink`.
4. **The host check is a substring.** `url.contains("trusted.com")`,
   `startsWith("https://trusted.com")` (passes `https://trusted.com.evil.net`)
   and `getHost().endsWith("trusted.com")` (passes `eviltrusted.com`) are
   bypasses; only an exact host match against an allowlist holds.
5. **Another app can claim the scheme.** A custom scheme carrying an OAuth code
   or a token can be intercepted by an app registering the same scheme; see
   `oauth_oidc_mobile`.

Attacker: **remote** when the scheme or link can be fired from a web page or a
QR code, which a custom scheme always can. Say what the victim does: tap a link.

## Clipboard

### What the app puts there

`ClipboardManager.setPrimaryClip(ClipData.newPlainText(...))` with a password,
OTP, PIN, recovery phrase, token or card number. Any foreground app, keyboard
or accessibility service can read it, and before Android 13 the clipboard
preview shows it. Mitigations to look for: the value is not copied at all;
`ClipDescription.EXTRA_IS_SENSITIVE` is set (Android 13+); the app clears the
clipboard after a short time. Attacker: **another app** or a malicious
keyboard.

### What the app takes from there

- Reading the clipboard on launch or on resume without the user pasting
  (`getPrimaryClip` in `onResume`, an SDK doing it) is a privacy finding.
- A pasted value acted on without confirmation: a payment address, IBAN or
  link pasted and used directly. An app that swaps the clipboard between copy
  and paste redirects the payment. The defence is to re-display the value
  (or its checksum) before acting.
- A clipboard value used as a URL or command is another untrusted source; trace
  it like a deep-link parameter.

### Sensitive fields

Password, PIN and card fields should use `textPassword`/`numberPassword` input
types, which keep them out of suggestion caches and block copying. A field
showing a secret in plain text with copy enabled is a small but real leak.

## Writing it up

For a link: the intent filter, the handler line, what the link does, and the
exact URL that does it. For the clipboard: the call that writes or reads it,
the value involved, and who can read it on the app's minimum supported
Android version.
