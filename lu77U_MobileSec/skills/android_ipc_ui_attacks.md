# Android IPC and UI-Layer Attacks

Classes another app on the same device - or a web page through a link - uses
against an app's components and screens. Each entry: what the attack is, what
to look for in the decompiled code, and what closes it. Read the manifest first
(`manifest_review`): most of these need an exported component or a reachable
entry to matter.

## Intents and components

- **Intent redirection.** An exported component reads an `Intent` (or a
  `PendingIntent`) from an extra and starts it: `startActivity((Intent)
  getIntent().getParcelableExtra("next"))`. The attacker reaches the app's
  private components, and with `FLAG_GRANT_*` flags its private files. Closed
  by never launching an Intent from input, or by checking its component against
  an allowlist.
- **intent:// URLs.** `Intent.parseUri(url, URI_INTENT_SCHEME)` on a URL from a
  WebView or a link, then `startActivity`. Closed by `setComponent(null)`,
  `setSelector(null)` and `addCategory(BROWSABLE)` on the parsed Intent.
- **Mutable or implicit PendingIntent.** `PendingIntent.get*` with an empty or
  implicit base Intent and without `FLAG_IMMUTABLE`, handed to another app
  (notifications, widgets, alarms). The receiver fills in the target and acts
  with the app's identity. A mutable one whose base Intent names its component
  cannot be redirected: the holder can only fill in fields the base left
  empty, such as extras, so it matters only when that component acts on them.
- **Content providers.** SQL built from `selection`, `sortOrder` or URI segments;
  `openFile` resolving a path from the URI without a canonical-path check;
  `grantUriPermissions` on an exported provider; a FileProvider with
  `root-path`. Test with `content query --uri ... --where "1=1"` and `../`
  segments.
- **Broadcasts.** Exported receivers acting on extras with no permission;
  `sendBroadcast` of sensitive data with an implicit Intent (any app can
  receive it); `registerReceiver` without `RECEIVER_NOT_EXPORTED` on Android
  14+ targets. A receiver of an ordered broadcast that reads the result
  (`getResultData()`, `getResultExtras()`, `getResultCode()`) trusts whatever
  an earlier receiver left there, and any app registering the same action at
  a higher priority runs earlier and rewrites it; one that acts on that result,
  or passes it on with `setResultData()`, is injectable. A receiver for a
  system broadcast is spoofable only if it acts on what another app can send:
  protected actions (`BOOT_COMPLETED`, `DEVICE_STORAGE_LOW`, `BATTERY_LOW`,
  `PACKAGE_ADDED` and the rest) cannot be sent by any app but the system, even
  explicitly, so one that checks `getAction()` for such an action before acting
  is safe from that, and one that acts on any intent it receives is not.
- **Bound services.** AIDL or Messenger services exported without a permission
  and without checking `Binder.getCallingUid()`.
- **Fragment injection.** An exported `PreferenceActivity` whose
  `isValidFragment` returns true (or that targets API 18 or lower) instantiates
  any fragment named in the `:android:show_fragment` extra.
- **Parcel mismatch.** A custom `Parcelable` whose `writeToParcel` and
  `createFromParcel` read and write different fields; across a Bundle round
  trip the attacker smuggles extras past a check.

## Code and data the app loads

- **Dynamic code loading.** `DexClassLoader`/`PathClassLoader` or
  `System.load` on a file in external storage, a downloaded file, or a path from
  input, with no signature check.
- **Zip Slip.** Extracting `ZipEntry.getName()` into a directory without
  checking the canonical path writes `../` entries anywhere the app can write -
  its preferences, databases, or a native library it loads next.
- **Deserialization.** `ObjectInputStream.readObject` on bytes from a file,
  socket or Intent; Gson/Jackson with polymorphic type handling enabled.

## Screens and input

- **Tapjacking.** An overlay (`SYSTEM_ALERT_WINDOW`, a toast) over a sensitive
  button tricks the user into tapping it. Closed by
  `filterTouchesWhenObscured`, or `setHideOverlayWindows(true)` on Android 12+.
  A finding when the button grants a permission, confirms a payment or changes
  security settings.
- **Task hijacking (StrandHogg).** An app with a matching `taskAffinity` slides
  its activity into the victim's task and shows a fake login. Look for
  activities with a foreign or empty affinity combined with `singleTask`,
  `allowTaskReparenting`, or targets below Android 11.
- **Accessibility abuse.** Sensitive views not marked
  `setAccessibilityDataSensitive` (Android 14+) or `importantForAccessibility`
  can be read by an accessibility service the user was talked into enabling.
- **Biometrics without a key.** `BiometricPrompt.authenticate` with no
  `CryptoObject`: success is a callback a hook can call. A finding when it
  gates anything a server does not separately check.
- **Screen capture.** No `FLAG_SECURE` on screens showing card numbers, OTPs or
  recovery phrases: they land in screenshots, screen recordings and the recents
  thumbnail.
- **Notifications.** OTPs, balances or messages shown with public lock-screen
  visibility.

## Attacker and severity

Almost everything here is **another app** on the device: an installed
application with no special permission. That is a realistic attacker, but it is
local - score it as such. A path becomes **remote** only when a web page can
start it, typically through a BROWSABLE intent filter or a WebView. Say which,
and how you know the component is reachable.
