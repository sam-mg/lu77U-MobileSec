# Offensive Android Testing — Proving Findings at Runtime

Practical exploitation techniques for Android apps, scoped to the tools this system
actually gives you in dynamic verification: `adb` (scoped to the target app),
`frida` (JS hooks attached to the target app), `read_source` (read the app's own
decompiled code), `note`, and `verdict`. Every technique below maps to one of those
tools directly, or is called out explicitly as an informational/manual-follow-up
note when it isn't something this loop can execute itself. (Static-phase tools like
`inspect_native` are not available here — their results are already baked into the
findings and the "App structure" hints.)

## Static → runtime mapping

| Static finding | How to prove it at runtime |
|---|---|
| Exported Activity/Service/Receiver without permission | `adb`: `am start -n <pkg>/<Component>` (or `am broadcast -n <pkg>/<Receiver> -a <action>`) and confirm it runs — this is the same effect a malicious app's implicit/explicit intent would have |
| Insecure data storage (plaintext SharedPrefs/SQLite/files) | `adb`: `run-as <pkg> cat files/...` or `run-as <pkg> ls shared_prefs/` to read the file directly off the sandbox |
| Hardcoded secret / API key | `frida`: hook the class/method that uses it and log the value at runtime, or `adb`: `dumpsys package <pkg>` / `logcat` if it's logged |
| Weak/no certificate validation | `frida`: hook the app's `X509TrustManager.checkServerTrusted` / `HostnameVerifier.verify` and observe it accept an obviously-invalid input — proves the check is a no-op without needing a live MITM session |
| Root/jailbreak or debugger detection | `frida`: hook the detection method (`File.exists` for su paths, `Debug.isDebuggerConnected`, etc.) and confirm forcing its result changes app behavior |
| Unsafe native (JNI) call | The exported symbol + risky imports were already captured in Phase 1 (shown in the finding / "App structure"); at runtime, `frida` — `Interceptor.attach(Module.getExportByName('lib<name>.so', 'Java_<pkg>_<Class>_<method>'), {...})` — hook the native export, trigger it (launch the activity that calls it via `adb am start`), and observe it being hit to prove reachability |
| WebView JS bridge (`addJavascriptInterface`) | `frida`: hook the bridge object's exposed method and call it with a benign payload to show it's reachable from JS |
| Biometric auth not bound to a key | `frida`: hook `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded` and observe you can force success without real biometric input |

## Frida hook patterns

```javascript
// SSL/TLS pinning bypass — generic X509TrustManager
Java.perform(() => {
  const TrustManager = Java.use('javax.net.ssl.X509TrustManager');
  // Locate the app's own TrustManager/HostnameVerifier implementation (search_code
  // for "TrustManager"/"HostnameVerifier" in Phase 1 first) and hook its
  // checkServerTrusted/verify to always pass — then attempt a request and observe
  // it succeeds despite an invalid cert, proving the check doesn't actually gate anything.
});

// Root detection bypass
Java.perform(() => {
  const File = Java.use('java.io.File');
  File.exists.implementation = function () {
    const path = this.getAbsolutePath();
    if (path.includes('su') || path.includes('magisk')) return false;
    return this.exists();
  };
});

// Biometric bypass — unbound BiometricPrompt callback
Java.perform(() => {
  const Cb = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
  Cb.onAuthenticationSucceeded.implementation = function (r) {
    return this.onAuthenticationSucceeded(r); // force success
  };
});
```

Keep hooks small and targeted at the specific class/method the static finding named —
a universal "hook everything" script wastes the step budget and produces noisy
`send()` output that's harder to turn into clean evidence.

## Exported-component / IPC exploitation via adb

```
am start -n com.vendor.app/.SecretActivity
am start -n com.vendor.app/.SecretActivity --es url "javascript:alert(1)"
am broadcast -n com.vendor.app/.BootReceiver -a android.intent.action.BOOT_COMPLETED
```

`am start`/`am broadcast` must target the app under test explicitly (`-n <pkg>/...`
or `-p <pkg>`) — the tool rejects anything else. This is enough to prove an exported
component is reachable and to exercise it with attacker-controlled extras.

## Insecure storage extraction via adb

```
run-as com.vendor.app ls shared_prefs/
run-as com.vendor.app cat shared_prefs/auth.xml
run-as com.vendor.app cat databases/app.db   # note: SQLite binary, not human-readable as text
```

Confirms sensitive data actually lands unencrypted in the app's private storage —
stronger evidence than a static "insecure storage" finding alone.

## Native (JNI) review

The static phase already ran the symbol table (`objdump -T`) on each `.so`, so a
native finding already names the exported `Java_<package>_<Class>_<method>` entry and
the risky libc imports it uses (`strcpy`, `strcat`, `sprintf`, `system`, `exec*`,
`gets` — classic memory-safety/injection-prone calls). You don't re-run that here.

To PROVE such a finding at runtime, use `frida`: hook the native export and show it's
reached with attacker-controlled input.

```javascript
// Prove an unsafe JNI method is reachable and takes user input.
Interceptor.attach(Module.getExportByName('libnative.so', 'Java_com_vendor_app_Foo_check'), {
  onEnter(args) { send('native Foo.check() hit'); },
});
```

Then trigger it (`adb am start -n <pkg>/<Activity>` for the screen that calls it, or a
Frida `Java.perform` call into the wrapper method) and observe the hook fire. If a full
disassembly/decompilation is needed to characterize the bug further, that's a
Ghidra/IDA follow-up outside this system — note it as a recommendation rather than
attempting it here.

## Firebase / cloud misconfiguration (static — grep, then note the URL)

```
search_code "firebaseio\.com"
search_code "amazonaws\.com"
search_code "\.appspot\.com"
```

Confirming these live (`curl https://<project>.firebaseio.com/.json` returning data,
an S3 bucket allowing public read/write) requires a plain internet request outside
this system's device-scoped tools — record the extracted URL as evidence and note it
as a finding to verify manually, rather than treating it as `not_verified` for lack
of a way to test it here.

## Repackaging / smali patching (rarely applicable)

apktool (`apktool d/b`) can decode resources + smali, patch a check (e.g. flip a
premium/paywall boolean), and rebuild + `apksigner sign` + `adb install -r` to test
the patched behavior. This is a manual, host-side workflow outside this agent's tool
surface (not something to attempt via `adb`/`frida`) — mention it as a recommended
technique in the report when a finding is specifically about client-side logic that
tampering could bypass, not something to execute here.

## TLS interception (informational)

This pipeline uses **mitmproxy** for HTTPS interception when the environment sets
it up as part of device readiness checks. The dynamic-verification
loop itself does not drive a live mitm session — use the Frida `checkServerTrusted`
hook above to prove pinning/validation is broken without needing one.

## Detection quick-reference

| Detector | What breaks it (for reference — don't attempt unless it's the finding under test) |
|---|---|
| Frida-server detection (port 27042) | Irrelevant here — this system already runs Frida to test; if the app blocks *because* Frida is attached, that itself is worth noting as a finding |
| Root/Magisk detection | Hook `File.exists`/`Runtime.exec("su")` as above |
| Emulator detection | Note as a limitation if it blocks testing on this device; not something to bypass mid-verification |
| Certificate pinning | Hook the TrustManager/HostnameVerifier as above |
| Play Integrity / server-side attestation | Out of scope — cannot be bypassed client-side; note as a hard limitation in the verdict reason if it blocks testing |
