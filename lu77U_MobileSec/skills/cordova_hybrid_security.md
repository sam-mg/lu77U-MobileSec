# Cordova / PhoneGap hybrid app security

Reference guidance for auditing an Apache Cordova / PhoneGap app. The app's real
logic is plain HTML/JS/CSS under `assets/www/`; the attack surface is the web
layer plus the native bridge Cordova exposes to it. Read `config.xml` first - it
defines the trust boundary.

## config.xml - read this first

- **Network whitelist.** `<access origin="*">` lets the WebView load any remote
  origin; a remote page then runs with the app's bridge access. Flag a wildcard
  or an overly broad origin. `<allow-navigation href="*">` is worse - it lets the
  top-level WebView itself navigate anywhere.
- **Intent whitelist.** `<allow-intent>` controls which URLs hand off to other
  apps.
- **Content-Security-Policy.** Look for the CSP `<meta>` tag in `index.html`. A
  missing CSP, or one with `unsafe-inline` / `unsafe-eval` / `*`, removes the
  main defence against injected script.
- **Plugins.** Each `<plugin>` / `<feature>` is a native capability reachable
  from JavaScript. `cordova-plugin-file`, `-inappbrowser`, `-file-transfer`,
  webintent and SQLite plugins are the high-value ones - map which pages use
  them.

## DOM-based XSS reaching the bridge

The defining hybrid risk: untrusted input reaching a DOM sink, because in a
Cordova app injected script inherits the app's native-bridge privileges (S:C).

- Sinks: `innerHTML`, `outerHTML`, `document.write`, `insertAdjacentHTML`,
  jQuery `.html()`, `eval()`, `new Function()`, `setTimeout`/`setInterval` with a
  string argument.
- Sources: `location.href`/`location.hash`/`location.search`, `handleOpenURL`
  (deep links), `FileReader` results, WebIntent extras, message-event data,
  responses from a whitelisted-but-untrusted origin.
- Trace source → sink. A hash fragment written into `innerHTML` on load is a
  classic reflected DOM-XSS; if that page can call `cordova.exec` or a file
  plugin, escalate the impact accordingly.

## The native bridge

- `cordova.exec(success, fail, service, action, args)` is the raw bridge call.
  Any script that reaches it can invoke native plugin actions.
- **InAppBrowser** (`window.open(url, '_blank')` / `cordova.InAppBrowser.open`)
  opened on an attacker-influenced URL, especially with
  `executeScript`/`insertCSS`, bridges attacker content into the app context.
- **File plugin** (`requestFileSystem`, `resolveLocalFileSystemURL`,
  `FileTransfer`): path traversal in a filename, or downloading to a
  world-readable location, or reading sensitive files under attacker control.
- **WebIntent** (`startActivity`, `getExtra`): launching arbitrary intents or
  trusting intent extras as input.

## Storage and secrets

- `localStorage` / `sessionStorage` / `openDatabase` (WebSQL) / SQLite plugin are
  unencrypted on-device by default. Flag credentials, tokens or PII stored there.
- Hardcoded API keys, tokens, private keys, and backend endpoints are shipped in
  plaintext in the bundled JS - grep for them and cite the exact line.

## Transport

- Cleartext `http://` endpoints, or `https://` with no pinning, are interceptable
  - the app trusts the platform CA store from inside a WebView. Combined with a
  wildcard whitelist this is remotely exploitable.

## Client-side crypto

- `CryptoJS`/`crypto-js` and hand-rolled `md5`/`sha1` used for anything security-
  relevant (password hashing, token signing) is weak and runs where an attacker
  can read and modify it. Treat client-side crypto as obfuscation, not security.

## What to prioritise

Entry pages (`index.html` and anything with `deviceready`) and any script that
both reads an untrusted source and reaches a DOM sink or the Cordova bridge.
Skip the Cordova runtime itself (`cordova.js`, `cordova-js-src/`) and vendored
libraries - they are noise, not the app's code.

## Before you report any of this

Two things have to be settled for every class above, and the answers differ per
class - `vulnerability_classes` lists them, `finding_quality` is the bar.

- **Name the thing.** Not "the component is exported" but what a caller gets;
  not "a key was found" but which service it authenticates to; not "data is
  stored insecurely" but which value and how it leaves the device.
- **Alone, or one of a pair?** Missing certificate pinning, `allowBackup="true"`,
  cleartext permitted by configuration, an unencrypted local database - each is a
  step. Report it with the other step named, or at Informational. See
  `chain_building` for which pairs are worth looking for.
- **Never on its own**: a debuggable build, missing root detection, missing
  obfuscation, missing ASLR/PIE, a certificate bundled in the APK, analytics
  collection. They are notes about the build. Say them once, at Informational,
  and spend the severity on something exploitable.
