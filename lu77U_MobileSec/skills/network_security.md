# Network & Transport Security

When the code touches networking, these are common places a weakness hides —
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
