# AndroidManifest Review

When you read `AndroidManifest.xml`, these are the well-known issues to check
first - not the full extent of what's worth flagging. Anything else about the
manifest's actual configuration that looks security-relevant is fair game.

- **`android:debuggable="true"`** - debuggable in production (Critical).
- **`android:allowBackup="true"`** (or unset on older targets) - app data can be
  extracted via `adb backup`.
- **`android:exported="true"`** on Activities/Services/Receivers/Providers without
  a `permission` - externally invokable components. Cross-reference each exported
  component with its implementing class for unprotected sensitive behaviour.
- **`android:usesCleartextTraffic="true"`** or no Network Security Config -
  cleartext HTTP allowed.
- **Custom permissions** with `protectionLevel="normal"` guarding sensitive actions.
- **`<provider>`** with `grantUriPermissions` or weak path permissions.
- **Dangerous permissions** the app requests - note any that seem excessive for the
  app's stated purpose (location, SMS, contacts, microphone, camera, storage).
- **`minSdkVersion`** too low, re-enabling deprecated insecure behaviour.
- **`taskAffinity` / `launchMode`** combinations enabling task hijacking.
- **Backup rules** (`fullBackupContent`, `dataExtractionRules`) that don't exclude
  sensitive files.

Report each manifest finding with `file` = `AndroidManifest.xml` and the relevant
attribute/component in `location`.

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
