# Deep-Link Endpoints - From the Link to the Session

A deep link is the one entry point a remote attacker reaches with nothing but
a URL: a web page, a chat message, an ad or a QR code fires it, and the victim
only taps. The outcome worth hunting is the session - the access or refresh
token, an authenticated request the attacker chooses, or a privileged action
taken in the victim's name. Most real cases are not a single bad line but a
path: link, handler, router, WebView or forwarded Intent, and finally the
token. Work in two passes: list every endpoint first, then put each one through
four lenses. An endpoint missing from the list is never analysed, so the list
is the work.

## 1. Build the endpoint list before analysing anything

Where endpoints come from:

- Manifest `intent-filter`s with `VIEW` + `BROWSABLE` and a `<data>` scheme,
  host, `path`/`pathPrefix`/`pathPattern`; `activity-alias` entries; `https`
  links with `android:autoVerify`. A custom scheme is fireable from any page.
- Routes registered in code or resources: navigation graphs
  (`res/navigation/*.xml` with `<deepLink app:uri=...>`), a router's mapping
  table (string to class or fragment), a React Native `linking` config, a
  Flutter router fed by `app_links`/`uni_links`/a `MethodChannel` from
  `onNewIntent`.
- Both handler methods: `onCreate` and `onNewIntent`. A `singleTop` or
  `singleTask` activity receives later links in `onNewIntent`; a check written
  only in `onCreate` is skipped there, and the reverse.
- Trampoline activities that parse the link and forward it without a layout.

Write one record per endpoint:

| Field | What to note |
|---|---|
| URI shape | `scheme://host/path?param=…`, with the parameter names the code actually reads |
| Receiver | The component that gets the Intent, and whether it is exported |
| Branch | The condition that selects this behaviour (`host == "open"`, `type == "web"`) |
| Parameters | Each value read (`getQueryParameter`, `getPathSegments`, `getLastPathSegment`, `getFragment`, a hand-split `getEncodedQuery`) and where it goes |
| Code | File and line of the handler and of every sink the values reach |

An endpoint is a behaviour, not a string. `app://item?id=1` and
`app://item?id=2` are one endpoint. `app://open?type=notice&id=1` (a native
screen) and `app://open?type=web&url=…` (a WebView) share a host and path and
are two, because a parameter picks a different branch. Two URIs that reach the
same branch with the same parameters are one record, so the same code is not
analysed twice.

Before moving on, walk every `if`/`when`/`switch` on scheme, host, path and
parameter values in each handler and confirm each arm has a record. Kotlin
`when` over strings compiles to a `hashCode()` switch, but the case literals
are still there to read.

## 2. Follow routers to internal endpoints

Many apps expose one public router - an exported activity that reads `target`,
`page`, `screen`, `route` or `path` and starts a non-exported activity or
fragment by name or table lookup, passing the remaining parameters along as
extras. Those internal screens are reachable from the web even though the
manifest says `exported="false"`.

- Record each as an **internal endpoint** with its forwarding path: external
  URI, router branch, internal component, the parameters handed over.
- An internal route on its own is a **primitive**, not a finding. It becomes
  one when the internal screen does something sensitive with the values it is
  given: loads a URL in an authenticated WebView, performs an account action,
  shows private data. Say which, with the line.
- A WebView opened by a link that itself handles `intent://` or custom-scheme
  navigation (`shouldOverrideUrlLoading` turning the URL into an Intent and
  starting it) makes any script that runs in that page a launcher for the
  app's internal components. Treat the WebView as a second router.

## 3. Four lenses for every endpoint

Each lens asks one question. Put every endpoint, internal ones included,
through all four, then report each path once: one flaw seen through two lenses
is one finding that mentions both; two separate flaws that combine are a
chain.

### A. WebView injection - does an attacker page get the session?

- **Who picks the URL.** A link parameter (directly or through the router)
  that becomes the URL an in-app WebView loads. Read the allowlist check.
  Only an exact host match on the parsed URL holds:
  `Uri.parse(u).getHost()` compared with `equals` to a fixed host, with the
  scheme required to be `https`. Bypassed: `contains`, `startsWith`,
  `endsWith` (`eviltrusted.com`), an unanchored regex, a check on the raw
  string before decoding, userinfo (`https://trusted.com@evil.net`), a
  backslash or encoded slash, `javascript:`/`file:`/`data:` schemes, and an
  open redirect on an allowed host.
- **What the page is given.** List every `@JavascriptInterface` method on each
  object passed to `addJavascriptInterface` and what it returns or triggers.
  The dangerous shape is a method that fetches, refreshes or signs with the
  session and delivers the result back to the page - often through a callback
  name the page supplies, run as `evaluateJavascript(callback + "(" + json + ")")`.
  The page never reads the token from storage; it asks the app to produce it.
  In React Native the equivalent is an `onMessage` handler that answers with
  session data through `injectJavaScript`/`postMessage`; in Flutter, a
  `JavascriptChannel` or `addJavaScriptHandler` that does the same.
- **What the app attaches.** `loadUrl(url, headers)` with an `Authorization`,
  cookie or token header; `CookieManager.setCookie` for a domain the link can
  change; `postUrl` with session data in the body; the token written into the
  page with `evaluateJavascript` or a `javascript:` URL.
- **Whether the bridge checks the caller.** An origin check has to run on
  every call, against the page's current URL, because the page can navigate
  after load; a check made once in `onPageFinished` is not one.
  `addWebMessageListener` with an explicit allowed-origin set is the safe
  form.

### B. Intent redirection - does the session ride along?

- A link parameter or extra chooses the next component: a class or package
  name, a nested Intent (`getParcelableExtra`), a URI turned into an Intent.
- Before forwarding, the app adds a token, user id or auth header as an
  extra, or grants `FLAG_GRANT_READ_URI_PERMISSION` /
  `FLAG_GRANT_WRITE_URI_PERMISSION` on its own provider.
- Sinks: `startActivity`, `startService`, `sendBroadcast`, `setResult`.
- Holds: an explicit component inside the app's own package checked after
  `resolveActivity`, no grants, no session extras on anything leaving the app.

### C. intent:// parsing - can a string become any Intent?

- `Intent.parseUri(value, Intent.URI_INTENT_SCHEME)` (or flags `0`) on a link
  parameter or a URL the WebView navigates to. The parsed Intent can name any
  component, including the app's own non-exported ones (the app starts them
  as itself), and carry extras (`S.key=…`, `B.`, `i.`), flags and a selector.
- Holds: `addCategory(Intent.CATEGORY_BROWSABLE)`, `setComponent(null)`,
  `setSelector(null)`, and refusing an Intent that resolves inside the app.
- A `browser_fallback_url` opened in the app's own WebView goes back to lens A.

### D. Parameter and logic forgery - does a value change where or what?

- **Where requests go.** `host`, `server`, `api`, `base_url`, `callback`,
  `return_url`, `redirect`: if the app then sends its own authenticated request
  to that address, the token leaks with no WebView at all. Same for a token
  POSTed to a URL taken from the link.
- **What is acted on.** `amount`, `to`, `account`, `order_id`, `action=delete`
  executed on arrival with no confirmation screen.
- **What is skipped.** A parameter that marks the user logged in, skips the PIN
  or biometric screen, or enables a debug mode.

## 4. When the decompiler drops the handler

JADX sometimes emits an empty body, `Method dump skipped`, or
`Code decompiled incorrectly`. The behaviour is still in the APK: read the
method's smali, or search for the strings around it. A missing body is not
evidence that a check is absent, and a method named `isValidUrl` is not
evidence that it checks anything - read what it compares. In obfuscated code,
find the router by searching for `getQueryParameter(`, `getHost()`,
`getPathSegments(` and the scheme and parameter names from the manifest; they
cluster where the routing happens.

## 5. What a finding must show

A finding is the whole path with a line for every hop:

1. the exact link, URL-encoded where needed (`app://open?type=web&url=https%3A%2F%2Ftest.example%2Fp.html`);
2. the handler line that reads it;
3. each hop - router branch, internal component, WebView load, forwarded Intent;
4. the sink line;
5. what leaves the app and to whom.

A missing hop makes it a lead: say which hop is unproven. Class it by the step
that does the damage - `PLATFORM-02` for a link reaching a sink, `PLATFORM-04`
for a bridge handing out the session, `PLATFORM-03` for redirection and
`intent://` parsing, `AUTH-01` for a token sent where the link points - and
chain them when two separate flaws combine.

Severity follows the attacker: a link any web page can fire, one tap, ending
in the victim's session is remote with user interaction and full
confidentiality and integrity loss - for example
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` (8.1). An internal route with nothing
sensitive behind it is an informational lead.

How to demonstrate it, on a test device with a test account only:

- fire the link: `adb shell am start -a android.intent.action.VIEW -d '<uri>'`;
- from the web: an `<a href="<uri>">` link, or
  `intent://<host>/<path>#Intent;scheme=<scheme>;package=<package>;end`;
- for a bridge: a page on a host you control whose script calls
  `window.<BridgeName>.<method>(...)` with a callback that shows what came back.

The proof is that the value works: a returned token authenticates as the test
account outside the app. Never send a real user's token anywhere, and never
point a link at a host you do not control.
