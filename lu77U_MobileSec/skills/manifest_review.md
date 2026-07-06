# AndroidManifest Review

When you read `AndroidManifest.xml`, these are the well-known issues to check
first — not the full extent of what's worth flagging. Anything else about the
manifest's actual configuration that looks security-relevant is fair game.

- **`android:debuggable="true"`** — debuggable in production (Critical).
- **`android:allowBackup="true"`** (or unset on older targets) — app data can be
  extracted via `adb backup`.
- **`android:exported="true"`** on Activities/Services/Receivers/Providers without
  a `permission` — externally invokable components. Cross-reference each exported
  component with its implementing class for unprotected sensitive behaviour.
- **`android:usesCleartextTraffic="true"`** or no Network Security Config —
  cleartext HTTP allowed.
- **Custom permissions** with `protectionLevel="normal"` guarding sensitive actions.
- **`<provider>`** with `grantUriPermissions` or weak path permissions.
- **Dangerous permissions** the app requests — note any that seem excessive for the
  app's stated purpose (location, SMS, contacts, microphone, camera, storage).
- **`minSdkVersion`** too low, re-enabling deprecated insecure behaviour.
- **`taskAffinity` / `launchMode`** combinations enabling task hijacking.
- **Backup rules** (`fullBackupContent`, `dataExtractionRules`) that don't exclude
  sensitive files.

Report each manifest finding with `file` = `AndroidManifest.xml` and the relevant
attribute/component in `location`.
