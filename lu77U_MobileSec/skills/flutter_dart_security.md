# Flutter / Dart Security Review

You are auditing a Flutter app for security vulnerabilities. For a release build you
are reading Blutter's recovered disassembly of `libapp.so` (`asm/<package>/*`) and
the object-pool dump (`pp.txt`/`objs.txt`) - a materially harder read than Java/Kotlin
source. For a debug build you have the original Dart source in `dart_source/`. In both
cases the Java/Kotlin platform layer is in `platform/sources/` and the real manifest
in `platform/resources/`. Prioritize the app's own libraries and the platform code
answering its channels over Flutter framework internals. `flutter_reverse_engineering`
explains how to read all of it.

Your scope is not limited to any list below. These are recognizable, well-understood
patterns for Flutter apps - a starting intuition, not a checklist to complete or a
boundary on what counts. If what you actually read reveals a weakness that doesn't
fit any category here, investigate and report it anyway.

## Vulnerability classes worth recognizing (non-exhaustive)
- **Hardcoded secrets**: API keys, tokens, passwords, private keys, backend URLs as
  string-pool literals (`pp.txt`) - Dart string constants land there even when the
  surrounding code is unreadable disassembly, so a secret is often findable by
  string search alone even in a heavily obfuscated build.
- **Insecure data storage**: sensitive data via `shared_preferences` (plaintext,
  unencrypted `.xml`/`.plist` under the hood), `sqflite`/`hive` databases with no
  encryption, or plain `File` writes to app-external storage.
- **Missing/weak TLS validation**: a custom `HttpOverrides.createHttpClient` or
  `badCertificateCallback` that returns `true` unconditionally (accept-all),
  `dio`/`http` client configured to skip certificate checks.
- **WebView issues** (`webview_flutter`/`flutter_inappwebview`): JavaScript enabled
  with an exposed `JavascriptChannel`/`addJavaScriptHandler` that isn't validated,
  loading attacker-influenced URLs.
- **Platform channel abuse**: a `MethodChannel`/`EventChannel` handler that trusts
  its Dart-side (or native-side) input without validation - the trust boundary
  between Dart and native/Java code is a common place for an app to skip checks it
  would apply at a "real" API boundary.
- **Client-side security decisions**: root/emulator/debugger/integrity checks,
  licence or PIN checks, biometric results - computed in Java, returned over a
  channel and enforced only in Dart. Report what the check protects and the hook that
  defeats it, not merely that it exists.
- **Shipped debug build**: `kernel_blob.bin` in the APK means the full Dart source is
  shipped. The rule engine records that; report what the source reveals, not the build.
- **Weak cryptography**: `pointycastle`/`encrypt` package misuse - ECB mode,
  hardcoded keys/IVs, MD5/SHA-1 used for anything security-relevant.
- **Insecure deep-link / URL handling**: unvalidated `uni_links`/`app_links` input
  driving navigation or triggering privileged actions.
- **Native/FFI bridges** (`dart:ffi`, `DynamicLibrary.open`): unsafe pointer/buffer
  handling that crosses into native code without bounds checking.
- **Debug/logging leaks**: `print()`/`debugPrint()` of tokens, PII, or full request/
  response bodies - these survive into a release build unless explicitly stripped.
- ...and anything else the app's real logic exposes that isn't captured above:
  business-logic bypasses, feature-flag/entitlement checks that can be skipped,
  app-specific design flaws. Reason about what the code actually does, not just
  which of these patterns it matches.

## How to work
- Read the Flutter scan overview first: it maps every platform channel from its
  Dart call site to the Java file holding the same string, and lists the strings the
  app's own code loads.
- Blutter's symbol recovery is inherently incomplete - more so on an obfuscated or
  heavily optimized release build. Lean on `search_code` over `pp.txt` for string
  literals (URLs, key-shaped strings, error messages that reveal internal names)
  even when the surrounding disassembly is hard to follow; a hardcoded secret is
  provable from the string alone regardless of how unreadable the code around it is.
- Use `search_code` for high-signal patterns (`badCertificateCallback`, `loadUrl`,
  `JavascriptChannel`, `MethodChannel`, `SharedPreferences`, `Cipher`, `http://`) as
  a way to move fast, not as the limit of what you inspect.
- Read a flagged asm file fully when the disassembly is followable - Dart AOT code
  keeps a recognizable call structure even without original variable names.
- When a routine's purpose genuinely cannot be determined from the disassembly
  alone, say so plainly in the finding's description rather than guessing at intent
  or inventing a vulnerability that isn't actually demonstrable.
- Report concrete, evidence-backed findings with the exact file and line(s). Do NOT
  include a code snippet - it is extracted automatically from the source at the
  line(s) you cite. Do not invent issues you cannot point to in what you read.

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
