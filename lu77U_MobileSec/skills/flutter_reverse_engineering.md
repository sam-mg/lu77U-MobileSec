# Flutter Reverse Engineering - Reading, Tracing and Proving a Flutter App

A Flutter app does not look like an Android app when you open it. The Java you
expect is a thin shell, the logic is compiled Dart, and the tools you would reach
for - JADX for the code, a proxy for the traffic, a `Java.use` hook for the checks -
each miss most of it. This skill is how to read what this system recovered, how to
move through it quickly, and what it takes to prove a Flutter finding.

Read the **Flutter scan overview** first. It says which build you have, where every
artifact is, and maps each platform-channel call from its Dart call site to the Java
file holding the same string.

## 1. Triage: which build is this?

| Build | What the APK ships | What you get here | How hard |
|---|---|---|---|
| **debug** | `assets/flutter_assets/kernel_blob.bin`, `isolate_snapshot_data`, `vm_snapshot_data`, **no** `libapp.so` | `dart_source/` - the original Dart, comments included; `dart_packages/<pkg>/` | Reads like source |
| **profile** | `libapp.so` (rarely shipped) | as release | |
| **release** | `lib/<abi>/libapp.so` + `libflutter.so` | `asm/<package>/<library>.dart` from Blutter, `pp.txt`, `objs.txt`, `blutter_frida.js` | Pseudo-Dart disassembly |
| **release, obfuscated** (`--obfuscate --split-debug-info`) | as release | `asm/` flat, files named like `aVc.dart`, names scrambled everywhere | Strings and constants are still in clear |

`kernel_blob.bin` and `libapp.so` are mutually exclusive in practice: the first means
a JIT debug build, the second an AOT build.

**A shipped debug build** means the complete Dart source is in the APK, comments and
all, and the app runs the JIT VM with assertions enabled. The rule engine records the
build itself (BUILD-01, a release-process note) - do not report it again. Its real cost
is what the source gives away: read it for keys, endpoints, disabled checks and TODOs
in comments, and report those.

The Blutter header (in the overview) gives the Dart version, snapshot hash and flags
such as `compressed-pointers` and `product`. The snapshot hash decides which
engine-patching tools support the build; the Dart version decides which Blutter
build was used.

Flutter is recognisable from outside too: `libflutter.so`, `assets/flutter_assets/`,
and `io.flutter.embedding.android.NormalTheme` / `flutterEmbedding` in the manifest.

## 2. The two halves of every Flutter app

```
Dart (libapp.so / kernel_blob.bin)            Java/Kotlin (classes.dex)
---------------------------------------       -------------------------------------------
UI, state, business logic, HTTP (dart:io)      FlutterActivity, plugin implementations,
                                               root/emulator/debugger/integrity checks,
MethodChannel('com.example.app/security')      biometric prompts, Keystore, WebView glue
  .invokeMethod('isDeviceTrusted')   ------>   MethodCallHandler:
                                                 if (call.method.equals("isDeviceTrusted"))
           <------  result.success(true) ----      result.success(checker.run());
```

Dart cannot read `/system`, query `PackageManager` or call the Keystore, so anything
security-flavoured that needs the OS lives in Java/Kotlin behind a **platform
channel** (`MethodChannel`, `EventChannel`, `BasicMessageChannel`). Plugins are the
same thing packaged: a Dart package plus Android code.

The thread that joins the halves is **the strings**: the channel name and each method
name appear verbatim on both sides, and R8 does not rename string literals. That is
why the overview can map them even when every Java class is called `a.b.c`.

The platform layer is ordinary Android attack surface and is in scope:
`platform/resources/AndroidManifest.xml` is the real manifest - exported components,
deep links (`flutter_deeplinking_enabled`, intent filters), `allowBackup`,
`debuggable`, and `platform/sources/` is the JADX output.

## 3. Reading Blutter output

### Layout

- `asm/<package>/<library>.dart` - one file per Dart library, headed
  `// lib: , url: package:<package>/<library>.dart`. The app is the package that owns
  `main()`; others are dependencies; `asm/flutter/` is the framework - skip it unless a
  call leads you there.
- `pp.txt` - the **object pool**: every constant in the snapshot. Strings
  (`[pp+0x8c10] String: "isDeviceTrusted"`), const objects with their fields
  (`[pp+0x5b30] Obj!LicenseScreen@4b17a1 : { off_c: "...the value..." }`), lists,
  type arguments, closures.
- `objs.txt` - every object with its nested objects written inline. A const widget
  tree lives here, not in `pp.txt`: the pool holds only
  `List<Widget>(4) [Obj!ListTile@585ed1, ...]`, and the strings those widgets display -
  a key on a hidden settings screen, say - are inside the `Obj!ListTile@585ed1 : {...}`
  block in `objs.txt`. Search `objs.txt` for secrets, not just `pp.txt`.
- `blutter_frida.js` - Blutter's Frida template, already able to decode Dart objects
  for this exact Dart version (section 7).

### Anatomy of a function

```
  _ _checkLicense(/* No info */) async {
    // ** addr: 0x2c41a8, size: 0x1c8            <- libapp.so offset: what Frida attaches to
    // 0x2c41a8: EnterFrame                          prologue
    // 0x2c41b0: AllocStack(0x80)
    // 0x2c41b4: SetupParameters(_LicenseState this /* r1 => r1, fp-0x68 */)
    //                                               where each parameter arrives and is saved
    // 0x2c41bc: CheckStackOverflow                  boilerplate - ignore
    // 0x2c41e0: InitAsync() -> Future<void?>        this is an async function
    // 0x2c41e8: r0 = isValid()
    //     0x2c41e8: bl #0x2c4f30  ; [package:acme_guard/guard.dart] Guard::isValid
    // 0x2c41f4: r0 = Await()                        suspends; resumes with the value in x0
    // 0x2c41f8: cmp w0, NULL                        <- first instruction after resume
```

Each annotated line (`// 0x...: r0 = isValid()`) is Blutter's pseudo-Dart for the
indented machine instructions under it. Read the annotations for meaning and drop to
the instructions only when the annotation is ambiguous.

### Registers and values (arm64 Dart AOT)

| Name in output | Register | Meaning |
|---|---|---|
| `PP` | x27 | object pool base - `[PP, #0x5b30]` is pool entry `0x5b30` |
| `THR` | x26 | current Dart thread - `[THR, #0x48]` stack limit and the like |
| `NULL` | x22 | the `null` object; `true` and `false` sit at fixed offsets from it |
| `HEAP` | x28 | heap base for compressed pointers |
| `fp` / `SP` | x29 / Dart stack | locals live at `fp-0x..`, incoming stack arguments at `fp+0x..` |
| `r0`/`x0` | x0 | return value, and the value an `Await()` resumes with |

- **Booleans:** `true` = `NULL + 0x20`, `false` = `NULL + 0x30`. You will see
  `add x1, NULL, #0x30 ; false` and bit tests like `tbnz w0, #4, <target>` - bit 4 is
  set in `false` and clear in `true`, so that line reads "if false, jump".
- **Small integers (Smi):** tagged with low bit 0; the value is the raw word shifted
  right by one. Blutter already prints them decoded (`r1 = 5`).
- **Heap objects:** tagged pointers with low bit 1; with `compressed-pointers` a field
  holds a 32-bit offset from `HEAP`. Do not decode by hand - use `blutter_frida.js`.
- **Fields:** `LoadField: r0 = r1->field_f` / `StoreField: r2->field_1b = r0` - the
  offsets match the `off_..` field names in `pp.txt` and `objs.txt`.
- **Write barriers:** the `tbz ... WriteBarrierWrappersStub` blocks after a store
  are GC bookkeeping - skip them.

### Calls, closures and async

- `bl #0x2c4f30 ; [package:acme_guard/guard.dart] Guard::isValid` - every call is
  annotated with its library and function, which is how you follow the code across
  files without a call graph.
- Stubs worth recognising: `AllocateClosureStub`, `AllocateContextStub`,
  `InitAsyncStub`, `AwaitStub`, `ReturnAsyncStub`, `ReturnAsyncNotFutureStub`,
  `StackOverflowShared...Stub`, `WriteBarrierWrappersStub`.
- **Closures** are declared `[closure] void <anonymous closure>(dynamic)` and created
  with `r1 = Function '<anonymous closure>':. ; [pp+0x8d48] AnonymousClosure:
  (0x2c5110), in [...] _LicenseState::_checkLicense (0x2c41a8)` - the address in
  brackets is the closure's own body. Button handlers (`onPressed`), `setState`
  callbacks and `then()` continuations are all closures.
- **Async functions** compile to a state machine. Calling one returns a `Future`
  immediately; the real value only exists where the caller's `Await()` resumes, in
  `x0`, at the instruction after the `AwaitStub` call. This changes how you hook them
  (section 7).

### Values built at runtime

A secret that never appears as a string is often a constant list plus a transform:
a `const [..]` list loaded from the pool, a `map`/`xor` closure, then
`String.fromCharCodes` / `createFromCharCodes`. You can usually recover it
statically: read the list in `pp.txt`, read the closure body, apply the transform.
When the transform is too involved, hook the function's return instead (section 7).

## 4. A search playbook

1. **Start from what the user sees.** Search the visible text of a screen, a button or
   an error message. It is in `pp.txt` and in the `r16 = "..."` loads of the widget's
   `build`. From the widget, find the `onPressed`/`onTap` closure and follow its call.
2. **Follow the overview's channel map.** For each method name, read the Dart call site
   (what is done with the answer) and the Java handler (how the answer is computed).
3. **Search the app packages for sinks:** `HttpClient`, `Dio`, `badCertificateCallback`,
   `SecurityContext`, `SharedPreferences`, `FlutterSecureStorage`, `Hive`, `sqflite`,
   `Cipher`/`Encrypter`/`Key.fromUtf8`, `WebViewController`, `JavaScriptChannel`,
   `launchUrl`, `MethodChannel`, `DynamicLibrary`, `print`/`debugPrint`.
4. **Identify the plugins.** Each third-party package under `asm/` (or
   `dart_packages/`) is a pub.dev package with public source. Its name tells you what
   it does - root/jailbreak detection, secure storage, biometrics, pinning - and its
   public Android code tells you which Java strings to look for.
5. **Endpoints and keys** sit in `pp.txt`, or in `objs.txt` when they are held by a
   const object. The overview lists the strings the app's own code loads, including
   those inside the const objects it references, which is a far shorter list than the
   whole pool.
6. **Obfuscated build:** class, function and library names are scrambled throughout,
   the framework included, but strings, constants and channel names are not. Work from
   strings outward, and use call structure (an `invokeMethod` call site, a `Cipher`
   construction) rather than names.

## 5. Debug builds

`dart_source/` is the developer's code, verbatim. Search and read it as you would
Java: comments frequently hold credentials, internal URLs and TODOs about disabled
checks. `dart_packages/` holds every dependency's source at the exact version used -
check versions against known advisories when a package handles crypto, networking or
storage.

## 6. Plugins and platform code that matter

- **`shared_preferences`** - plaintext XML at
  `shared_prefs/FlutterSharedPreferences.xml`, keys stored with a `flutter.` prefix.
  A token or PIN written there is readable on a rooted device and in backups.
- **`flutter_secure_storage`** - Keystore-backed on Android; misuse is about what is
  stored and when it is read, not the storage itself.
- **`sqflite` / `hive` / `isar`** - local databases, unencrypted unless the app adds
  encryption; check what goes in.
- **`local_auth`** - the biometric result returns to Dart as a boolean over a channel;
  if nothing server-side depends on it, it is a client-side gate.
- **Root / jailbreak / emulator / debugger detection** (`flutter_jailbreak_detection`,
  `safe_device`, freeRASP and others) - the checks run in
  Java, often wrapping RootBeer, and every branch returns through the same
  `MethodChannel.Result.success(...)` call. One hook on that sink, or on the Dart side
  where the result is awaited, defeats all of them.
- **`webview_flutter` / `flutter_inappwebview`** - `JavaScriptChannel` /
  `addJavaScriptHandler` expose Dart to page script; check what URLs load and what the
  handler does with input.
- **`url_launcher`, `app_links`, `uni_links`** - deep links that drive navigation;
  check what an attacker-supplied link can reach.
- **Firebase** - configuration lands in `platform/resources/res/values/strings.xml`
  (`google_api_key`, `firebase_database_url`, `google_storage_bucket`); test the
  backend's rules before calling a public identifier a leak.

On the Java side, find a handler by searching `platform/sources` for the method
string. In R8-obfuscated code it is still a comparison against the literal
(`((String) call.f5c).equals("isDeviceTrusted")`), and the boolean leaves through a
single obfuscated `Result` method - that method is the hook point.

## 7. Network and TLS: why the usual setup sees nothing

Flutter's HTTP (`dart:io`, and `http`/`dio` on top of it) opens sockets from the Dart
VM and verifies TLS with the BoringSSL statically linked into `libflutter.so`. So:

- it **ignores the Android proxy setting** - a Wi-Fi proxy captures nothing;
- it **does not use `network_security_config.xml`** and installing a CA into the
  Android store is not enough;
- therefore **"no traffic in the proxy" is not evidence of pinning**, and a missing
  `network_security_config` is not a Flutter finding by itself.

Static signals:

- `badCertificateCallback` set to a closure that returns `true` - certificate
  validation disabled; a real finding when it guards anything sensitive. In a release
  build the setter's name is gone: `(cert, host, port) => true` compiles to Dart's shared
  always-true closure, so look for `Object::_simpleInstanceOfTrue` passed to
  `AllocateClosure` and stored (`StoreField`) into the `_HttpClient` the same function
  just built. A hand-written closure that returns true loads `NULL + 0x20`.
- A pinning attempt that **fails open**: the pinned `SecurityContext` built inside a
  `try`, with the `catch` returning a default `HttpClient()` - any error in the pin
  setup silently disables it.
- `SecurityContext(withTrustedRoots: false)` + `setTrustedCertificatesBytes(...)` -
  pinning to an embedded certificate; the certificate bytes are in the pool or
  `flutter_assets`.
- `dio` `IOHttpClientAdapter` / `onHttpClientCreate` / `createHttpClient` overriding
  the client; pinning plugins (`http_certificate_pinning` and similar).

Dynamic interception, cheapest first:

1. **frida-flutterproxy** - finds `Socket_CreateConnect` / `GetSockAddr` and
   `ssl_crypto_x509_session_verify_cert_chain` in `libflutter.so` by string reference
   (`"ssl_client"`) and patterns, redirects sockets to your proxy and forces chain
   verification to succeed. Needs no transparent proxy and **works against pinning**.
   Use the build matching your Frida major version (17+ versus earlier).
2. **NVISO `disable-flutter-tls`** - pattern-scans for `ssl_verify_peer_cert` and
   patches it to succeed; needs a transparent proxy (ProxyDroid / iptables) because it
   does not redirect sockets; can **fail against pinning** that takes the other
   verification path.
3. **reFlutter** - patches `libflutter.so` in the APK and re-signs it. Breaks any
   signature or file-integrity check, and from Flutter 3.24 it no longer hardcodes a
   proxy, so it also needs a transparent proxy.

Finding the function by hand when patterns miss: open `libflutter.so` in Ghidra,
search for the string `ssl_client`, follow its references, and take the function with
three parameters - that is `ssl_crypto_x509_session_verify_cert_chain`. Ghidra loads
the library at image base `0x100000`; subtract it to get the offset Frida needs.

WebView traffic is separate: it uses the Android stack and the normal proxy.

## 8. Frida on Dart code

Start from `blutter_frida.js` - it already decodes Dart objects for this Dart version
(`init(this.context)`, `getTaggedObjectValue(ptr)`, `NullReg`, `CidString`). Offsets
are the `** addr:` values, relative to `libapp.so` with no image base to subtract.

**Read a return value** (synchronous function):

```javascript
function onLibappLoaded() {
  const fnAddr = 0x3a0d14;                         // ** addr: of the function
  Interceptor.attach(libapp.add(fnAddr), {
    onEnter() { init(this.context); },
    onLeave(retval) {
      const [tptr, cls, value] = getTaggedObjectValue(retval);
      console.log(`${cls.name} = ${JSON.stringify(value)}`);
    }
  });
}
```

**Force a boolean** (synchronous function):

```javascript
onLeave(retval) {
  retval.replace(this.context[NullReg].add(0x20));  // true; 0x30 is false
}
```

**Async functions** return a `Future`, not the value - hooking their entry or exit
changes nothing useful. Hook the caller instead, at the first instruction after its
`Await()` (the line after `bl AwaitStub`), where `x0` holds the resolved value:

```javascript
Interceptor.attach(libapp.add(0x2c41f8), {           // first instruction after Await()
  onEnter() {
    init(this.context);
    const [, cls, value] = getTaggedObjectValue(this.context.x0);
    console.log(`resolved ${cls.name} = ${JSON.stringify(value)}`);
    this.context.x0 = this.context[NullReg].add(0x30);   // force false
  }
});
```

Hooking `ReturnAsyncStub` itself also works but rewrites the result of **every**
async function in the app - timers, navigation, everything - so use it only to
confirm a theory.

**Startup checks race the hook.** A check in `initState()` runs once, early. Spawn the
app (`frida -U -f <package> -l script.js`) and poll for `libapp.so` every 100 ms
rather than 500 ms, or the check runs before the hook exists.

**Platform side** - hook the Java handler or its `Result` sink with `Java.perform` /
`Java.use` as for any Android app; one hook on the sink covers every method the
handler answers.

## 9. What makes a defensible Flutter finding

- **Cite the real place**: `asm/<app>/<lib>.dart:<line>` (or `dart_source/...`, or
  `platform/sources/...`), the function's name, and for a release build its
  `libapp.so+0x...` offset - that offset is the reproduction step.
- **A hardcoded secret**: cite the line that loads it and the `pp.txt` entry; say what
  it unlocks. A string nothing uses is a note.
- **A client-side check** (root, license, PIN, biometric, feature flag): name where the
  decision is made (often Java), where it is enforced (Dart), and the hook that flips
  it. It is a finding when it protects something the user should not get; root and
  emulator detection alone are defence-in-depth, reported low.
- **TLS**: an accept-all `badCertificateCallback` is evidence; absence of pinning is
  not proven by a silent proxy - say what was and was not intercepted.
- **Platform channels**: a handler that acts on Dart-supplied arguments (paths, URLs,
  SQL, intents) without validation is an input-validation finding on the Java side.
- **Do not report** the Flutter framework's own code, "obfuscation not enabled",
  "no root detection", or a build flag on its own.
