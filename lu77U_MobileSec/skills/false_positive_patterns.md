# False-Positive Patterns - Android Decoys That Look Like Bugs

Decompiled Android code is full of shapes that trip a pattern match but are not
findings. `finding_quality` decides whether a real issue is worth reporting;
`evidence_discipline` decides what a proof licenses you to claim. This is the layer
before both: a candidate matched a rule - is it even real, or one of the known decoys?
Each pattern below is a shape that reliably produces a report a maintainer marks "not
applicable," paired with the one check that kills it or confirms it. Run the check
before you write the finding.

The rule is not "distrust every match." It is: these specific shapes have a known
answer, so resolve them deterministically instead of filing the alarm.

## The gate for each decoy

| Decoy shape | Why it fires | The check that settles it | If it survives |
|---|---|---|---|
| Exported component | `exported="true"` or an intent-filter present | Is there a guarding `android:permission`, and what is its `protectionLevel`? A `signature` permission means only same-signer apps reach it | PLATFORM-01, only if unguarded or guarded by a `normal`/`dangerous` permission a third party can hold |
| The launcher / a sync or account component | Exported and unguarded | Does it *have* to be exported (MAIN/LAUNCHER, a `SyncAdapter`, an `AccountAuthenticator`, an input method)? Framework-required exports are not the finding | Only if it also takes and acts on external input |
| "Secret" string | Regex hit on key/secret/token/password | Is it a *value* or an *identifier/label*? A JSON key name, a `SharedPreferences` key, a log tag, or a public client identifier (OAuth client id, `google_app_id`, a provider-restricted Maps key) is not a leaked credential | SECRET-01 for a real value; SECRET-03 for a public identifier with the provider-side restriction missing |
| Placeholder / fixture secret | Looks like a key | Is it `"YOUR_API_KEY_HERE"`, `"changeme"`, all-zeros, `"test"`, or a documented example value? A placeholder authenticates to nothing | Nothing - it is not a secret |
| Weak digest (MD5/SHA-1) | `MessageDigest.getInstance("MD5")` | What does the digest protect? A cache key, ETag, file-dedup checksum, or cache-buster is not a security use | CRYPTO-01 only when it protects data whose integrity or secrecy matters |
| `Cipher.getInstance("AES")` | Matches "no mode" and "ECB default" both | It is one issue, not two - and only a finding when it protects sensitive data. Deduplicate the alarm | CRYPTO-01 once, if the plaintext is sensitive |
| `java.util.Random` | Flagged as weak randomness | What is the value used for? An animation seed, a jitter/backoff, a non-security nonce is fine | CRYPTO-03 only in a security context (token, IV, salt, key) |
| WebView with JS enabled + a bridge | `setJavaScriptEnabled(true)` + `@JavascriptInterface` | What origin does it load? Only bundled `file:///android_asset/` content with no externally influenced URL cannot be driven by an attacker | PLATFORM-04 only when *untrusted* content can reach the bridge |
| `usesCleartextTraffic` / missing pinning / `allowBackup` | Config flag present | Configuration is not behaviour or impact. Is there an actual HTTP request in code, sensitive data in the backup, an interception path? | Non-standalone (NETWORK-02/03, STORAGE-04) - needs a chain partner; see the taxonomy |
| `if (BuildConfig.DEBUG)` block | A risky call (log-of-token, debug endpoint, trust-all) inside it | Does the guard exclude it from the release build? A debug-only path is not shipped behaviour | Nothing, unless the guard can be flipped without rebuilding |
| Match inside a bundled SDK | Pattern in decompiled third-party code | Shipped code counts, so do not dismiss it for living under a library/generated path - but does the *app's own* code reach that path? A vulnerable branch nothing invokes is a code-quality note | Real only with a caller from an app entry point |
| `DexClassLoader` / reflection | Dynamic loading flagged | Can the loaded path or class name be influenced from outside? A fixed name loaded from internal storage is not attacker-controlled | CODE-02 only when the source of the loaded code is external |
| Dangerous permission declared | `<uses-permission>` for a dangerous permission | Is it actually used, and by the app or a bundled SDK? A declared-but-unused or SDK-required permission is inventory, not misuse | A finding only when paired with the misuse it enables |
| Exported provider with `grantUriPermissions` | Looks locked down by the grant | `grantUriPermissions` does *not* protect general provider access - but a `readPermission`/`path-permission` guard does. Check which is present | PLATFORM-01 / CODE-01 if the provider is reachable and its queries are injectable |

## Three gates worth stating on their own

**The value-versus-name gate.** Before any secret, permission, or "sensitive" string
finding: is the match a value an attacker could use, or the *name* of a field, a UI
label, a resource identifier, or a public identifier? Half of secret false positives
die here. A `String PASSWORD_KEY = "password"` is a preferences key, not a password.

**The reachability gate.** Before any injection, deserialization, command-exec, or
dynamic-loading finding: trace one caller back to an entry point an attacker touches -
exported component, deep link, network response, WebView content. A perfect
vulnerability in a method nothing invokes is a note, not a finding. If you cannot find
the caller, say so and downgrade rather than assuming it.

**The configuration-versus-impact gate.** Before promoting any manifest or config flag:
a flag *permits* a weakness; it is not the weakness. `allowBackup`, cleartext capability,
and absent pinning are non-standalone in the taxonomy for this reason. Report the
configuration once, at its real weight, and only escalate when you can add the behaviour
and the impact that make it exploitable.

## When a decoy survives, say why

Resolving a decoy is itself useful output. When you clear one - the export is
signature-guarded, the "key" is a public client id, the MD5 is a cache key - a one-line
note saying you checked and why it is not a finding is worth more than silence: it tells
the maintainer the surface was examined, not missed, and it stops the same shape being
re-filed later. A finding you kept and a decoy you cleared are both results.
