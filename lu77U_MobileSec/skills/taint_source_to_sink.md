# Source-to-Sink Tracing - Turning a Sink Into a Path

A dangerous API on its own is not a finding, and neither is an exported entry point.
The finding is the **path** between them: attacker-controlled data entering at a source,
flowing through the app, and reaching a sink where it does harm. `finding_quality` and
`false_positive_patterns` both stop you at a reachability gate - "trace one caller back
to an entry point". This is the method for actually walking that path in decompiled
code, so the gate becomes a concrete answer instead of a guess.

The point is interprocedural: the source, the sink, and the sanitizer that would break
the path are usually in different methods and different classes. A scanner that matches
a sink in isolation produces both false negatives (misses a real path) and false
positives (assumes a path a helper actually sanitises). Following the data across those
boundaries is the whole job.

## The two directions, and which to walk

- **Backward, from the sink.** Grep the sink APIs (there are few of them), then walk
  *up* the call graph asking "where does this argument come from?" until you reach a
  source (a finding), a real sanitiser (not a finding), or an internal constant (not
  reachable). This is usually faster because sinks are rarer than sources.
- **Forward, from the source.** Start at an exported component or deep link, follow the
  extracted value *down* through the methods that touch it until it hits a sink or is
  discarded. Use this when the entry point is the thing you already have.

Pick the shorter side. Most Android findings are fastest found backward from the sink.

## Sources - where attacker data enters

| Source | The API to grep | Trust note |
|---|---|---|
| Intent extras | `getIntent()`, `getStringExtra`, `getParcelableExtra`, `getSerializableExtra`, `getBundleExtra` | Attacker-controlled when the component is exported or deep-linked |
| Deep link data | `getData()`, `getQueryParameter`, `getPathSegments`, `getLastPathSegment` | Attacker-controlled if a victim can be made to open the link |
| Content provider input | `query()` selection/`selectionArgs`, the `Uri` path/segments | Attacker-controlled when the provider is exported |
| Broadcast | the `Intent` delivered to `onReceive` | Attacker-controlled unless the receiver is permission-guarded |
| WebView | `@JavascriptInterface` method parameters, `postMessage`, URL query params | Attacker-controlled when the WebView can load untrusted content |
| Network response | OkHttp/Retrofit body, headers | Semi-trusted: relevant against a malicious or intercepted server |
| Shared/external files, clipboard | `getExternalFilesDir`, world-readable reads, `ClipboardManager` | Attacker-controlled if another app can write the source |
| Bound service / Messenger / AIDL | the `Bundle`/`Parcel` from another app | Attacker-controlled when the service is exported |

## Sinks - where tainted data does harm

| Sink | The API to grep | Class if reached tainted |
|---|---|---|
| SQL | `rawQuery`, `execSQL`, `ContentResolver.query` with a concatenated selection | CODE-01 |
| File path | `new File(...)`, `FileInputStream`, `openFileOutput`, `FileProvider` path | PLATFORM-11 (traversal) |
| WebView load | `loadUrl`, `loadData`, `loadDataWithBaseURL`, `evaluateJavascript` | PLATFORM-04 / PLATFORM-06 |
| Reflection / dynamic load | `Class.forName`, `Method.invoke`, `DexClassLoader`, `loadClass` | CODE-02 |
| OS command | `Runtime.exec`, `ProcessBuilder` | CODE-02 |
| Intent redirection | `startActivity`/`startService`/`sendBroadcast` on a source-derived `Intent` | PLATFORM-03 |
| Deserialization | `readObject`, `Parcelable` unmarshalling, typed JSON binding | CODE-03 |
| Crypto input | a source value used as a key/IV in `Cipher`/`SecretKeySpec` | CRYPTO-02 (context) |
| Egress of a secret | `Log.*`, an outbound URL/param carrying it | SECRET-02 / NETWORK-04 |

## Propagators - how taint moves between the two

Taint follows the data, not the variable name. It propagates through:

- Assignment, and **fields** - `onCreate` stashing `getIntent().getData()` into a field
  that `onClick` later reads is one path across two callbacks. Lifecycle callbacks are
  the classic place a naive trace loses the trail.
- String work - concatenation, `String.format`, `StringBuilder.append`, `Uri.parse`,
  `Uri.Builder`, `Bundle.get*`, collection put/get.
- **Method boundaries** - when a tainted value is passed to a helper, follow the helper
  and trace its parameter; when a method returns a value derived from a tainted argument,
  the return is tainted. This is the interprocedural hop scanners skip.
- Parsing - `Gson`/`Jackson`/`Moshi` binding a tainted string into a typed object taints
  that object's fields.

## Sanitisers - what actually breaks the path

A sanitiser on the path kills the finding, but only a *real* one does:

- **Breaks taint**: an exact allowlist (`equals` against a fixed set), a parameterised
  query (value goes in as a bind argument, not concatenated), canonicalisation followed
  by a prefix check for a path, a scheme+host allowlist for a URL, strict type/enum
  validation, output encoding matched to the sink (`TextUtils.htmlEncode` before HTML).
- **Does not break taint**: a blocklist, a `contains()`/`startsWith()` substring check, a
  length cap, client-side-only validation, or encoding for the wrong context. These look
  like protection and routinely produce a false "it's handled" dismissal - verify the
  check is on the actual value and actually rejects the payload class.

When you find a sanitiser, decide which kind it is before you clear the path. When you
clear one, say which check breaks the taint and why - that is a resolved decoy
(`false_positive_patterns`), useful output in itself.

## What the trace produces

Record the path as: the **source** (named, and why it is attacker-controlled), each
**propagation hop** as `file:method`, the **sink** (named), and any sanitiser you ruled
out and why. That list *is* the "attacker's steps from entry point to impact" that
`finding_quality` requires and the entry/target pair that `chain_building` links. A path
you completed is a finding; a path a sanitiser breaks is a note; a sink you could not
walk back to any source is a code-quality lead, reported as one - never as the sink's
full severity.
