# React Native Reverse Engineering - Reading, Tracing and Proving a React Native App

A React Native app keeps its logic in a JavaScript bundle and its device access in Java.
Each half hides the other: the bundle never shows what a native method does with its
arguments, and the Java never shows which screen trusts which flag. This skill is how
to read what this system recovered, how to join the two halves, and what it takes to
prove a React Native finding.

Read the **React Native scan overview** first. It gives the engine and bytecode
version, the React Native version, the manifest, every native module with the JS that
calls it, the entitlement and role flags (`isPremium`, `isAdmin`) the app's JS reads,
and the WebView, storage, URL and credential leads.

## 1. Triage: engine, version, architecture

| Question | Where the answer is | Why it matters |
|---|---|---|
| Plain JS or Hermes? | bundle header: Hermes starts `c6 1f bc 03 c1 03 19 1f`, then the bytecode version (little-endian u32) | plain JS can be read and edited as text; Hermes needs a decompiler and a version-matched assembler |
| Bytecode version | the overview (`HBC version NN`) | every Hermes tool supports a range of versions; check the real number, never infer it from the app's age |
| React Native version | `ReactNativeVersion` in `platform/sources/com/facebook/react/modules/systeminfo/` | decides which classes exist (`ReactNativeHost` vs `DefaultReactNativeHost`, bridge vs bridgeless) |
| Old bridge or new architecture | `libreactnativejni.so` (bridge glue) vs `libfabricjni.so` / `libturbomodulejsijni.so` (Fabric, TurboModules) | bridge-level hooks (`CatalystInstanceImpl`) only exist on the old bridge; new architecture is default from 0.76 and bridgeless apps have no bridge to hook |
| Is the shipped bundle what runs? | CodePush / `expo-updates` in the platform layer or bundle | an over-the-air update can replace the bundle at runtime - the APK's bundle may be stale |

Libraries in `lib/<abi>/`: `libhermes.so` (Hermes), `libjsc.so` (JavaScriptCore), `libjsi.so`
(JSI, both architectures).

## 2. Reading what this system gives you

### Layout

- `app_modules/<id>_<name>.js` - the app region: the app's own Metro modules plus the
  libraries it imports (storage, WebView, navigation, safe-area). Each file starts with
  `// Module ID`, `// Name` and `// Dependencies: [ids]`.
- `framework_modules/` - React Native itself. Skip it unless a lead goes there.
- `platform/sources/` - JADX Java/Kotlin; `platform/resources/AndroidManifest.xml`.
- `secrets.txt`, `modules.txt` - hermes-decomp's string-table secret scan and module list.

Module 0 is the entry (`AppRegistry.registerComponent`). Its non-framework dependency
is the root component; everything the app does hangs off that.

### Plain (minified) bundles

```javascript
function(g,r,i,a,m,e,d){          // global, require, importDefault, importAll, module, exports, depMap
  var t=r(d[0]);                   // require(dependencies[0]) - see the header's Dependencies list
  e.default=function(n){           // the module's default export
    var p=n.isPro;                 // a prop read
    return p?(0,s.jsxs)(...):(0,s.jsxs)(...)   // JSX: render one tree or the other
  }
}
```

- `r(d[N])` requires the module whose id is the **Nth entry** of this file's
  `Dependencies` list - that is how you follow a call to its module file.
- `(0,o.jsx)(c.View,{...})` is JSX; `children:"..."` holds the visible text.
- `!0` is `true`, `!1` is `false`, `void 0` is `undefined`.
- Gates read as ternaries or `&&`: `p?(<paid view>):(<locked view>)`.

### Hermes (decompiled) bundles

- `import X from "name" /* 503 */` - the comment is the module id; names come from the
  bundle's string table and survive minification of locals.
- `closure_1[5]` - a value captured from an enclosing scope, usually a required module.
- Logic is reconstructed from bytecode: control flow and constants are faithful, local
  names (`tmp4`, `arg0`) are not.

## 3. A search playbook

1. **Start from the screen text.** Search the words the user sees (a "Pro" label,
   "Admin", an error string) to find the screen module, then the condition that decides what it
   renders and where that value comes from - a login response, a prop, storage.
2. **Storage:** `setItem`, `getItem`, `multiSet` and their keys - what lands in AsyncStorage.
3. **Network:** `fetch`, `axios`, `XMLHttpRequest`, base URLs, and the headers sent
   (`Authorization`, `x-api-key`) - a static key sent from the client is a shared secret.
4. **Native modules:** `NativeModules.`, `TurboModuleRegistry.get` - then the Java class
   from the overview.
5. **WebView:** `onMessage`, `injectedJavaScript`, `originWhitelist`, `source:{uri:`.
6. **Deep links:** `Linking.getInitialURL`, `Linking.addEventListener`, a navigation
   `linking` config with `prefixes` - what a crafted link can reach.
7. **Dangerous JS:** `eval(`, `new Function(`, `crypto-js` with fixed keys or IVs.

## 4. Native modules - the Java half

A native module is a class extending `ReactContextBaseJavaModule` (or a codegen
`Native*Spec`). `getName()` returns the name JavaScript uses (`NativeModules.<name>`),
and only methods annotated `@ReactMethod` are callable. Arguments arrive as JS values;
results go back through a `Promise` or `Callback` parameter.

```java
public String getName() { return "SupportModule"; }

@ReactMethod
public void openLogFile(String path, Promise promise) {
    promise.resolve(readText(new File(path)));      // no check that path stays inside the app
}
```

- **Callable by any JS that runs in the app**, whether or not the bundle calls it:
  `NativeModules` is a proxy that is not enumerable, so absence from the bundle hides a
  module from a casual reader, not from an attacker. The overview marks app-owned
  modules nothing calls - those are the ones to read hardest.
- **Reachability is the severity question.** JS gets into the app through a WebView
  bridge that forwards messages to handlers, an over-the-air update, a debug build's
  debugger, or a patched bundle on a rooted device. Name the route you can show.
- Registration is in a `ReactPackage`'s `createNativeModules` (and `PackageList` /
  `MainApplication`) - a module in the APK but never registered is not callable.

## 5. WebView bridges (`react-native-webview`)

- `onMessage` handlers receive `event.nativeEvent.data` from any page loaded in the
  WebView; check whether the handler verifies `event.nativeEvent.url` before acting.
- `injectedJavaScript` / `injectedJavaScriptBeforeContentLoaded` run in the page;
  `originWhitelist={["*"]}`, `allowFileAccess`, `allowUniversalAccessFromFileURLs` and
  `mixedContentMode="always"` widen what the page can be.
- The page side calls `window.ReactNativeWebView.postMessage(...)`. An HTTP `source`
  URL, an open redirect or XSS on the loaded site turns that into an attacker channel
  into the app's handlers - and through them, possibly a native module.

## 6. Storage

- **AsyncStorage** is plain SQLite under the app's `databases/` directory (newer
  versions use a database named `AsyncStorage` with table `Storage`; older ones
  `RKStorage` with `catalystLocalStorage`). Readable on a rooted device and in a backup
  when `allowBackup` permits.
- Secure alternatives: `react-native-keychain`, `react-native-encrypted-storage`,
  `expo-secure-store`. `react-native-mmkv` is unencrypted unless given an `encryptionKey`.

## 7. Network and TLS

Unlike Flutter, React Native's `fetch`/XHR go through OkHttp in the platform layer, so
the device proxy and `network_security_config` apply and the usual Android interception
works. Pinning shows up as an `OkHttpClientFactory` set in `MainApplication`
(`OkHttpClientProvider.setOkHttpClientFactory`) with a `CertificatePinner`, or a pinning
library (`react-native-ssl-pinning`, TrustKit); OkHttp unpinning hooks defeat both.

To watch responses without a proxy at all, hook React Native's own network layer:
`com.facebook.react.modules.network.ResponseUtil` (`onResponseReceived`,
`onDataReceived`) and `NetworkingModule`. Responses read as blobs arrive as a
`{blobId, offset, size}` map; the bytes are in `com.facebook.react.modules.blob.BlobModule.store(byte[])`.
When rewriting a body there, keep its byte length identical - the size was recorded
before your hook ran.

## 8. Runtime instrumentation (Frida)

- **Inject JS (old bridge):** hook `com.facebook.react.bridge.CatalystInstanceImpl.loadScriptFromAssets`,
  call the original, then `loadScriptFromFile` on a payload the app can read (its
  files directory). The payload runs in the JS global scope: wrap
  `XMLHttpRequest.prototype.open`, set `XMLHttpRequest._interceptor`, wrap
  `JSON.parse`/`JSON.stringify`, or call a native module directly. `require` does not
  exist in a Frida script - JS-side work has to run inside the app's runtime.
- **Swap the bundle without touching the APK:** hook `ReactNativeHost.getJSBundleFile()`
  (`DefaultReactNativeHost` on newer versions) to return a patched bundle on the device.
- **Call a native module from Java:** `Java.choose('<module class>')` for the live
  instance, then call the `@ReactMethod` with your own `Promise` made with
  `Java.registerClass` - it must implement every `reject` overload or registration fails.
- **Drive a WebView bridge:** after the screen is open, attach (`-p <pid>`, not `-f`),
  `Java.choose('android.webkit.WebView')`, and inside `Java.scheduleOnMainThread` call
  `evaluateJavascript("window.ReactNativeWebView.postMessage(...)", null)`.
- Hooking Hermes itself (`HermesRuntimeImpl::call`) is unreliable on a stripped
  `libhermes.so`; prefer the Java and network layers.
- hermes-decomp can generate hooks for a module's exports:
  `hermes-decomp frida-hooks <bundle> --module <id>`.

## 9. Patching to prove a client-side check

- **Plain bundle:** edit the gate in the text (`p?A:B` to `1?A:B`), then either re-sign
  the APK or serve the edited file through the `getJSBundleFile` redirect.
- **Hermes bundle:** patch bytecode with a version-matched assembler, or hermes-decomp
  (`patch-string` for same-length strings, `patch-function` from HASM). Keep the byte
  length of the replaced instructions identical - jump targets are byte offsets, so a
  shorter instruction shifts every later branch and crashes the app.
- Re-signing breaks signature and integrity checks; the runtime redirect does not.

## 10. What makes a defensible React Native finding

- **Cite the real place:** `app_modules/<id>_<name>.js:<line>` or `platform/sources/...`.
- **Hardcoded key:** the module defining it and the request that sends it; say what it
  unlocks server-side. A key the backend never checks is a note.
- **Client-side authorization:** where the flag is read and the gate rendered, where it
  comes from, and that the server does not re-check - that last part is what makes it
  a vulnerability rather than a UI choice.
- **Native module:** the `@ReactMethod`, what it does with which argument, and the route
  by which JS reaches it.
- **WebView bridge:** the handler, what it trusts, what it can trigger, and how
  attacker content gets into the WebView.
- **Do not report** React Native's own framework modules, "no obfuscation", or a debug
  flag on its own.
