# Objection Runtime Toolkit - Translating Its Commands Into This Loop

Objection is a Frida-powered runtime exploration toolkit for mobile apps. On a human
tester's console it wraps the same instrumentation this loop reaches through `frida`
into short, memorable commands - disable SSL pinning, dump shared preferences, list
and dump SQLite databases, walk the filesystem, read/write class variables, call
methods, search memory - without root or a jailbreak.

**Objection itself is not one of this loop's tools.** The loop cannot spawn an
`objection` console; its runtime surface is `adb` (scoped to the target app), `frida`
(JS hooks attached to the target app), `read_source`, `note` and `verdict`. So treat
this skill two ways: as a reference you cite in a `note` for the manual follow-up a
human runs, **and** as a lookup table, because almost every objection command is a
packaged Frida script or `adb` shell call you can reproduce directly with the tools
you do have. When a finding says "objection can show this," reach for the loop
equivalent in the tables below and prove it in-loop rather than deferring everything
to a human.

## Starting a session (manual step only)

```bash
objection -g <package_name> explore        # attach to a spawned/running app
objection -g <package_name> explore --startup-command "android sslpinning disable"
```

`-g` is the package or gadget name (e.g. `com.example.app`). This is a human console;
in-loop, the equivalent of "attach" is a `frida` hook script that runs inside the same
process, and the equivalent of "explore the device" is `adb` scoped by `run-as <pkg>`.

## Command → what it proves → in-loop equivalent

| Objection command | What it demonstrates | Do it in this loop with |
|---|---|---|
| `android sslpinning disable` | Pinning is defeatable, so traffic is interceptable | `frida`: hook the app's own `X509TrustManager.checkServerTrusted` / `HostnameVerifier.verify` to a no-op (see `network_security`, `offensive_android`) |
| `android hooking list classes` / `... class_methods <cls>` | Enumerate the runtime surface | `frida`: `Java.enumerateLoadedClasses` / `Java.use(cls)` then enumerate methods (see `frida_hook_recipes`) |
| `android hooking watch class_method <cls>.<m> --dump-args --dump-return` | A method's real inputs/outputs at runtime | `frida`: an observation hook that calls through, then `send()`s args and return (see `frida_hook_recipes`) |
| `android hooking set class_variable <cls> <field> <val>` | A guard/flag is client-side and overridable | `frida`: `Java.use(cls).<field>.value = <val>` inside `Java.perform` |
| `android hooking call <cls>.<m> <args>` | A sensitive method is reachable/triggerable | `frida`: `Java.use(cls).<m>(args)`, or `adb am start`/`am broadcast` to reach the component that calls it |
| `android keystore list` / `... clear` | What's in the AndroidKeyStore and whether it's app-bound | `frida`: hook `java.security.KeyStore` / `KeyGenParameterSpec$Builder` and log alias/flags |
| `android shared_preferences` (a.k.a. `android prefs`) | Secrets/flags stored in plaintext prefs | `adb`: `run-as <pkg> cat shared_prefs/*.xml` |
| `android sqlite list` / `... dump <db>` | Sensitive data in the app's databases | `adb`: `run-as <pkg> ls databases/` then `run-as <pkg> sqlite3 databases/<db> '.dump'` (or pull and open) |
| `android fs ls <path>` / `fs download <path>` | Files readable in the sandbox | `adb`: `run-as <pkg> ls <path>` / `run-as <pkg> cat <path>` |
| `memory search "<pattern>" --string` / `memory dump all <file>` | A secret/key lives in process memory | `frida`: `Memory.scan` over `Process.enumerateRanges('r--')` for the pattern |
| `android root disable` | Root detection is client-side and bypassable | `frida`: hook the detection method (`File.exists` on su paths, `Runtime.exec`, package checks) - see `offensive_android` |
| `android intents launch_activity <cls>` / `launch_service` | An exported component is launchable by anyone | `adb`: `am start -n <pkg>/<cls>` / `am startservice` / `am broadcast` (see `offensive_android`, `chain_building`) |

## SSL pinning bypass - the objection default vs. what actually gates

`android sslpinning disable` hooks the common pinning implementations (OkHttp
`CertificatePinner`, `X509TrustManagerExtensions`, `TrustManagerImpl.verifyChain`,
Conscrypt, and the platform `TrustManager`). It is the fast first attempt. When it
does not work - a custom `TrustManager`, native pinning in a `.so`, or a
non-standard networking stack - objection has no more magic than a hand-written
Frida script does, and neither will this loop. In that case, `read_source` /
`search_code` for `TrustManager`, `HostnameVerifier`, `CertificatePinner`, or
`checkServerTrusted` in the app's own code, then hook the exact implementation you
find. Proving the check is a no-op (it accepts an obviously invalid input) is enough
evidence; you do not need a full live MITM session to substantiate the finding.

## Storage inspection - objection's coverage, mapped to `run-as`

Objection's `shared_preferences`, `sqlite`, `keystore` and `fs` commands all read the
app's private sandbox - exactly what `run-as <pkg>` gives you when the app is
debuggable, or what a rooted device gives you unconditionally. What matters for a
finding is not that objection can list the file, but that the file holds something
sensitive in the clear:

- **Shared preferences / XML**: tokens, PINs, "isPremium"/"isLoggedIn" flags stored
  plainly - read them, quote the exact key/value in the `note`.
- **SQLite**: dump the tables; a plaintext credentials/session table is the finding.
- **Keystore**: presence of a key is not a vulnerability; a key generated **without**
  `setUserAuthenticationRequired` / usable without unlock, or a secret kept outside
  the keystore, is. Log the `KeyGenParameterSpec` flags.
- **Filesystem**: cache/`files/`/external-storage artifacts (logs, exports, WebView
  caches) that leak data.

## Runtime manipulation - set, call, watch

The three objection verbs map one-to-one onto Frida:

```javascript
// set class_variable  - flip a client-side gate and show behaviour changes
Java.perform(() => { Java.use('com.example.app.Flags').isPremium.value = true; });

// call - invoke a sensitive method directly to prove it is reachable/unguarded
Java.perform(() => { const R = Java.use('com.example.app.Rewards'); R.grantCredit(1000000); });

// watch class_method - observe real inputs/outputs (call through, then report)
Java.perform(() => {
  const C = Java.use('com.example.app.Auth');
  C.checkPin.implementation = function (p) {
    const out = this.checkPin(p);
    send(`Auth.checkPin(${p}) -> ${out}`);
    return out;
  };
});
```

Setting a variable or forcing a return value changes app behaviour - do it only when
the finding is specifically that a check is client-side and defeatable, and always
call through first for a watch/observation hook (`frida_hook_recipes` explains why).

## Root / emulator / debugger detection bypass

The source's referenced `fridantiroot` codeshare script is a broad "hook everything
that smells like root detection" bypass:

```bash
frida --codeshare dzonerzy/fridantiroot -U -f <package_name>
```

Prefer a **targeted** hook over the shotgun script when you already know the detection
method from `read_source` - hook that one method, force its result, and show the app
proceeds. That is cleaner evidence and cheaper on the step budget than a universal
bypass. `offensive_android` has the targeted patterns.

## IPC / component exploitation - drozer (manual) and adb (in-loop)

Drozer is the classic console for enumerating and attacking exported components,
content providers and intent surfaces:

```bash
run app.package.attacksurface <package_name>
run app.provider.query content://<authority>/<path>
run app.activity.start --component <package_name> <activity>
```

In-loop, you do not need drozer: the static passes already listed the exported
components, and `adb` reproduces the attack - `am start`/`am broadcast` to launch a
component, `content query --uri content://<authority>` to hit an exported provider,
and `getIntent()`-fed extras to test input handling. Chain these into a concrete
attacker story (`chain_building`, `offensive_android`).

## Deep link and WebView exploitation

The source calls out deep-link and WebView attacks specifically. Deep links reach
`adb`: `am start -a android.intent.action.VIEW -d "<scheme>://<host>/<path>" <pkg>`
to fire an app-handled URI and see whether it drives a sensitive action without
authorization. WebView JS-bridge and `addJavascriptInterface` issues are covered in
`vulnerability_classes` and (for hybrid apps) `cordova_hybrid_security` /
`react_native_security`; hook the exposed bridge object to prove it is callable.

## Evidence discipline

Objection makes it trivial to *do* things to an app; a finding needs proof that the
thing *matters*. For every capability above, the note or verdict should carry the
concrete observation - the plaintext value read, the invalid cert accepted, the guard
flipped and the resulting behaviour change - not merely "objection could disable X."
Keep hooks small and targeted at the exact class/method the static finding named.
