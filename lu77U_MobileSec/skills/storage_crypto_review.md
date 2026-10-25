# Local Storage and Cryptography Review

Two questions decide every storage finding: **what is the value**, and **who can
read where it lands**. Two decide every crypto finding: **where does the key
come from**, and **does the scheme protect integrity as well as secrecy**.

## Where data lands on Android

| Location | Who can read it |
|---|---|
| `shared_prefs/*.xml`, `databases/*.db` (with `-wal`/`-journal`), `files/`, `cache/`, `app_webview/` | the app; anyone with root, a debuggable build (`run-as`), or a backup when `allowBackup` permits |
| `/sdcard/`, `getExternalFilesDir` on old Android, `MediaStore` | other apps with storage permission on older versions; the user |
| logcat (`Log.*`, `System.out`, `console.log`, Dart `print`) | `adb`; on Android 4.0 and earlier, any app with `READ_LOGS` |
| the clipboard | foreground apps, keyboards, accessibility services |
| crash and analytics SDK payloads | the SDK vendor |
| screenshots and the recents thumbnail | anyone with the device, unless `FLAG_SECURE` is set |

Framework stores are the same files under other names: AsyncStorage (SQLite
`RKStorage`/`AsyncStorage`), MMKV without an encryption key, Hive boxes without a
cipher, Flutter `shared_preferences`, Xamarin `Preferences`, Realm without an
encryption key. Encrypted options: Jetpack `EncryptedSharedPreferences`/
`EncryptedFile` (or Tink), SQLCipher, `flutter_secure_storage`,
`react-native-encrypted-storage`, MMKV or Realm with a key from the Keystore.

What makes it a finding: a credential, session token, PIN, key or personal data
in a store that is readable by someone the threat model cares about. A token in
`shared_prefs` with `allowBackup="false"` on a non-debuggable build is readable
only with root - say so, and rate it on that.

Also check: sensitive values cleared on logout (tokens, cached responses,
WebView cookies and storage); temp files from export, share, camera or PDF
features deleted after use; password and card fields using password input
types; `FLAG_SECURE` on screens that show secrets.

## Keys

| Where the key comes from | Verdict |
|---|---|
| a string or byte-array literal, `BuildConfig`, `strings.xml`, assets, gradle properties | hardcoded: anyone with the APK has it |
| a native library constant or an XOR-masked array | hardcoded, one step further away: a hook on the cipher call or the export prints it |
| derived from a device ID, package name, signing certificate or timestamp | predictable: every input is public |
| derived from the user's password with PBKDF2/scrypt/Argon2 and a random salt | acceptable when the iteration count is high (PBKDF2-SHA256 600,000+) |
| generated in the Android Keystore (`KeyGenParameterSpec`) | good; check whether high-value keys require user authentication and are invalidated on biometric enrolment |

Obfuscation, native code and string encryption change none of these verdicts.

## Schemes

- **Algorithm and mode.** `Cipher.getInstance("AES")` defaults to ECB. ECB, DES,
  3DES, RC4 and Blowfish are broken or obsolete. CBC without a MAC is malleable
  and can leak plaintext through padding errors. Use AES-GCM or
  ChaCha20-Poly1305.
- **IV and nonce.** A zero, constant or key-derived IV, or a GCM nonce reused
  under the same key. Each encryption needs a fresh random IV from
  `SecureRandom`.
- **Randomness.** `java.util.Random`, `Math.random()`, `new SecureRandom(seed)`
  or a time seed producing keys, IVs, tokens, OTPs or reset codes.
- **Hashing passwords.** MD5, SHA-1 or a single SHA-256 of a password, with no
  salt, is reversible by lookup.
- **Failure handling.** A `catch` around decryption or verification that
  returns the input, a default, or `true` fails open.
- **Home-made schemes.** XOR with a fixed string, Base64 called encryption,
  custom substitution loops. Name what they are.
- **Plaintext left behind.** Decrypting to a temp file or cache and not deleting
  it undoes the encryption.

## Native code

Keys and tables in `.so` files sit in `.rodata`: AES S-box bytes
(`63 7c 77 7b`), SHA-256 round constants, ChaCha's `"expand 32-byte k"` mark a
crypto routine. A key passed across JNI as a `byte[]` or `String` is visible to
a hook on either side. Comparing MACs with `memcmp` or `strcmp` leaks timing.
See `native_library_analysis`.

## Proving it

Statically: the line that builds the key or IV, where its value comes from, and
the call that uses it. At runtime, a hook on `Cipher.init`/`doFinal`,
`SecretKeySpec.<init>` and `Mac.doFinal` (see `frida_hook_recipes`) prints the
algorithm, key length and IV and settles any doubt about a derived key. Never
paste a real production key into the report: cite where it is.
