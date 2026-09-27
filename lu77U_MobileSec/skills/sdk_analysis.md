# Third-Party SDK Assessment

An embedded SDK runs with the app's full permissions and is trusted without
review. Apps ship SDK versions years behind, with debug features left on and
credentials in configuration files the SDK reads at startup. All of that is app
code as far as an attacker is concerned.

The scan already inventories SDKs deterministically. Your job is the part that
needs judgment: which of them matter here.

---

## Finding SDKs in the tree

- **Package directories.** `com/google/firebase/`, `com/facebook/`,
  `io/sentry/`, `com/appsflyer/`. These survive obfuscation because the SDK is
  shipped pre-built.
- **Native libraries.** `libhermes.so` (React Native), `libapp.so` +
  `libflutter.so` (Flutter), `libfb*.so` (Facebook), `libsqlcipher.so`.
- **Configuration assets.** `google-services.json`, `assets/appcenter-config.json`,
  `firebase_*` string resources.
- **String markers.** `"Firebase/"`, `"fb_sdk_version"`, `"sentry-"`.

---

## Getting the version

A version-less SDK finding is unverifiable, so extract it or say you could not.

| Source | Reliability |
|---|---|
| `BuildConfig.VERSION_NAME` inside the SDK's own package | High |
| `static final String VERSION` / `SDK_VERSION` in an SDK class | High |
| Gradle or Maven fragments left in decompiled resources | Medium |
| Version-shaped strings elsewhere in code | Low - often a build artefact |

Read the version from the SDK's *own* package. `BuildConfig.VERSION_NAME` in the
app's package is the app's version, not the SDK's - a common and confusing
mix-up.

---

## What to report

### Debug SDKs in a release build
Flipper, Stetho, Hyperion and LeakCanary each open a local debugging surface -
Stetho exposes a socket that speaks the Chrome DevTools protocol, giving any
local process the app's database and preferences. Their presence in a production
APK is a genuine finding at Medium, and often a build-configuration mistake the
team does not know about.

### Known-vulnerable versions
Report only when you can name the version *and* say whether this app's
integration reaches the vulnerable code path. An unreachable CVE is an upgrade
recommendation, not a vulnerability.

### SDK credentials
`google-services.json` contains an API key by design - that is not a leak, and
reporting it as one costs credibility. What matters is the key's *restrictions*,
which are set server side and cannot be read from the APK. Say what you found and
that its restrictions need checking. A Firebase database URL that turns out to be
world-readable is a real finding; the key sitting next to it is not.

### Misconfiguration
Analytics SDKs initialised with debug or verbose logging leave request bodies -
sometimes including tokens - in logcat.

---

## Framework SDKs change where to look

- **React Native**: the app's own logic is in the JavaScript bundle, not in Java.
  Java classes are mostly bridge glue. `AsyncStorage` is plain unencrypted storage.
- **Flutter**: logic lives in `libapp.so` as compiled Dart. Platform channels are
  the Java/Dart boundary and are where secrets tend to cross.
- **Cordova**: `assets/www/` is the whole app. `config.xml` allow-lists decide
  what the WebView may load, and a `<access origin="*"/>` there is the app
  permitting any origin.
- **Xamarin/.NET**: logic is in managed assemblies under `assemblies/`. These are
  typically not obfuscated, so extracted strings are unusually high-signal.

---

## Not a finding

The inventory itself. "This app embeds 23 SDKs" is context for the report, not a
vulnerability, and neither is the data those SDKs collect - that is a privacy and
disclosure question, answered by the app's policy rather than its code.
