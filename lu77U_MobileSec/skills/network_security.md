# Network & Transport Security

When the code touches networking, these are common places a weakness hides -
not a limit on what to look for. Follow the app's actual networking logic beyond
this list if it leads somewhere.

- **Certificate/hostname validation bypass**: custom `X509TrustManager` whose
  `checkServerTrusted` is empty, `HostnameVerifier` returning `true`,
  `SSLSocketFactory` trusting all, `setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER)`.
- **Cleartext traffic**: `http://` URLs, `usesCleartextTraffic`, OkHttp/Retrofit
  base URLs over HTTP.
- **Missing certificate pinning** for sensitive endpoints (note as informational
  unless the app handles high-value data).
- **Network Security Config** (`res/xml/network_security_config.xml`):
  `cleartextTrafficPermitted="true"`, `<trust-anchors>` including `user` CAs,
  `debug-overrides` shipped to production.
- **WebView TLS**: `onReceivedSslError` calling `handler.proceed()` unconditionally.
- **Sensitive data in URLs / query strings** (tokens, credentials, PII).
- **Insecure protocols**: FTP, Telnet, plain sockets carrying sensitive data.

Useful `search_code` patterns: `TrustManager`, `HostnameVerifier`, `http://`,
`onReceivedSslError`, `SSLSocketFactory`, `cleartextTrafficPermitted`,
`CertificatePinner`.

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
