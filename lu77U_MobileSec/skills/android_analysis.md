# Android Platform Behaviour

Facts about the platform that decide whether something is a finding. Most wrong
Android findings come from applying a correct rule at the wrong API level, so
this is the reference for that, plus the attack surfaces a keyword search will
not hand you.

---

## Read the manifest first

It is the only ground truth in a decompiled app. It names every externally
reachable entry point, and its SDK levels change what half the other rules mean.
Everything else in the tree is a decompiler's reconstruction of bytecode.

---

## SDK levels change the answer

`targetSdkVersion` is not a version number - it is the app opting into a set of
behaviours. Read it before scoring anything below.

| From targetSdk | What changes |
|---|---|
| 24 | User-installed CA certificates are no longer trusted by default |
| 28 | Cleartext HTTP is blocked by default |
| 31 | `android:exported` becomes mandatory - nothing is implicitly exported |
| 31 | `PendingIntent` requires an explicit mutability flag |
| 33 | Notification posting needs a runtime permission; media permissions split into `READ_MEDIA_IMAGES` / `_VIDEO` / `_AUDIO` |
| 34 | Exported receivers must declare an intent-filter; implicit intents can no longer reach the app's own non-exported components; background activity launches are restricted |
| 35 | Certificate transparency enforcement is available in the network security config |

Three findings depend on this directly, and getting them wrong is the most
common way an Android report loses credibility:

- **Implicit export** is real only below targetSdk 31. At 31 and above a missing
  `android:exported` is a build failure, not an exposed component.
- **Mutable PendingIntent** is real only below 31. At 31 and above the default
  flipped, so the finding needs an explicit `FLAG_MUTABLE`.
- **Cleartext** is permitted by default only below 28. Above it, the app must
  have opted back in through `usesCleartextTraffic` or a network security config.

`minSdkVersion` tells you the oldest platform the app still runs on. A low
minSdk means the *defaults above do not apply on every device the app supports*,
which is worth a note - but the code still has to do something with that.

---

## When is a component exported?

Three cases, in order:

1. `android:exported` present → it says what it says.
2. Absent, has an `<intent-filter>`, targetSdk < 31 → **exported**.
3. Absent, no intent-filter → not exported.

A component is only *protected* if it declares a `permission` whose
`protectionLevel` is `signature` or `signatureOrSystem`. `normal` and
`dangerous` are grantable to any app that asks for them, so they stop nothing.

`<provider>` needs more care than the rest:

- `grantUriPermissions="true"` lets it hand out access to URIs it would
  otherwise refuse.
- `<path-permission>` covers only the paths it names - anything else is
  unguarded.
- `<grant-uri-permission android:pathPattern="...">` with a wildcard root shares
  the whole tree.

---

## Permissions are context, not findings

A dangerous permission says what the app *could* do with a vulnerability, not
that it has one. These matter when something else makes them reachable:

- `SYSTEM_ALERT_WINDOW` - draw over other apps; the tapjacking primitive.
- `BIND_ACCESSIBILITY_SERVICE` - read all screen content and act on it.
- `MANAGE_EXTERNAL_STORAGE` - the whole shared volume.
- `REQUEST_INSTALL_PACKAGES` - sideload; a real escalation path if the app
  downloads and installs anything.

On their own they are an inventory line.

---

## Sources and sinks

Untrusted data enters here:

| Source | Call |
|---|---|
| Activity IPC | `getIntent()`, `onNewIntent()` |
| Service IPC | `onStartCommand()` extras |
| Deep link | `getIntent().getData()`, `getQueryParameter()` |
| WebView | `@JavascriptInterface` method arguments, `shouldOverrideUrlLoading` |
| Provider | `query()` selection, projection, and the URI itself |
| Activity result | `onActivityResult()` - the sender may be hostile |
| Network | response bodies |
| External storage | any file the app did not write |

And becomes dangerous here:

| Sink | Call | Result |
|---|---|---|
| Command execution | `Runtime.exec`, `ProcessBuilder` | code execution |
| WebView | `loadUrl`, `loadData`, `evaluateJavascript` | script execution, phishing |
| File | `FileOutputStream`, `new File(...)` | path traversal |
| IPC | `startActivity`, `sendBroadcast`, `setResult` | intent injection |
| Reflection | `Class.forName`, `getMethod`, `DexClassLoader` | code execution |
| JNI | native method calls | native execution |
| SQL | `rawQuery`, `execSQL` | SQL injection |

**A finding is a path between the two tables.** Report the path, not the sink. A
sink with no reachable source is a code-quality note.

---

## Surfaces a search will not find for you

These need reading, not grepping, and they are where the interesting bugs are.

**The validation gap between `onCreate` and `onNewIntent`.** A single-top or
singleTask Activity gets its first Intent through `onCreate` and every later one
through `onNewIntent`. Apps routinely validate in the first and not the second,
so the second delivery walks straight past the check.

**Task hijacking.** An Activity inherits the application's `taskAffinity`, which
defaults to the package name. Any other value is a string a malicious app can
also declare - and then the victim's Activity opens inside the attacker's task,
surrounded by attacker UI. Check `taskAffinity`, `allowTaskReparenting` and
`launchMode="singleTask"` together. `android:taskAffinity=""` is the fix, not
the bug.

**Tapjacking.** A transparent window over a sensitive control makes the user
authorise something they cannot see. The defence is
`filterTouchesWhenObscured="true"` on the view, or `FLAG_SECURE` on the window.
Their absence on a screen that confirms a payment or grants access is worth
reporting; on a settings toggle it is not.

**FileProvider path traversal.** `openFile()` builds a `File` from the caller's
URI. Without a `getCanonicalPath()` comparison against the intended root,
`../../databases/app.db` leaves the shared directory and the caller reads
anything the app can.

**Biometric prompts that gate nothing.** `BiometricPrompt` without a
`CryptoObject` produces a boolean the app chooses to trust. Bound to a Keystore
key created with `setUserAuthenticationRequired(true)`, the protected data
genuinely cannot be decrypted without the user. The first is bypassed by
returning `true`; the second is not.

**Second-order flows.** A value that is stored safely and read back unsafely
later. The write and the read are in different files and neither looks wrong
alone.

**Happy-path-only authorisation.** The permission check runs in the success
branch and the error branch returns the data anyway.

**Logout that only clears the UI.** The token is still valid server-side and
still in storage.

**Encoded rather than encrypted.** Base64, XOR or a custom alphabet in
authentication logic. It looks like crypto in a diff and is not.

---

## Reading decompiled Java

- **Obfuscated names are normal.** `oa.C0900k` is a class like any other.
  Obfuscation lands on the most interesting classes as often as the least, so
  never skip a file because its name is meaningless.
- **Search for annotations and API calls, not names.** The class holding
  `@JavascriptInterface` methods is usually not the class calling
  `addJavascriptInterface`, and neither has a useful name.
- **String constants survive obfuscation.** URLs, keys, SQL fragments and error
  messages are readable in even a heavily obfuscated app, and they are the
  fastest route into unfamiliar code.
- **`BuildConfig.DEBUG` guards do not run in release.** Check the guard before
  reporting debug-only code.
- **Decompilation artefacts exist.** Unreachable branches, odd casts and
  synthetic accessors come from the decompiler, not the developer.
- **Kotlin adds noise.** `Intrinsics.checkNotNullParameter`, `$this$` receivers
  and `WhenMappings` classes are compiler output. Coroutine bodies decompile into
  state machines with a `label` switch - the real logic is in the branches.

When names are gone entirely and strings are encrypted, see
`reading_obfuscated_code`.

---

## Reproduction commands for the report

The static agent does not run these. They belong in the finding so the owner can
confirm it.

```
adb shell am start -n <pkg>/<activity>                              # exported activity
adb shell am start -a android.intent.action.VIEW -d '<uri>' <pkg>   # deep link
adb shell content query --uri content://<authority>/<path>          # exported provider
adb shell content read --uri content://<authority>/../databases/x   # provider traversal
adb shell am broadcast -a <action> --es key value                   # exported receiver
adb backup -f out.ab <pkg>                                          # allowBackup
```
