# Xamarin / .NET MAUI Security

The app is .NET, not Java. The DEX is a launcher and a set of Mono bindings; the
logic lives in managed assemblies recovered from the APK. Two consequences shape
the whole review:

**Xamarin apps are usually not obfuscated.** ProGuard/R8 do not apply to managed
code, and .NET obfuscators are rarely added. Class names, method names and string
literals are typically intact, which makes this the easiest app type on Android
to read - and the reason a string dump alone is a productive scan.

**Half the app is still Android.** Exported components, deep links, the manifest
and the WebView all behave exactly as they do in a Java app. C# just holds the
logic behind them, so `vulnerability_classes` and `android_analysis` apply in full.

---

## What you are reading

| File | What it is |
|---|---|
| `assemblies.txt` | The inventory. App assemblies first, framework after. Read it first. |
| `*.cs` | Decompiled C#. Read as source. |
| `<Assembly>.dll.txt` | Literal strings from an assembly that was not decompiled. |
| `*.dll` | The assembly itself, binary - the `.txt` beside it is the readable form. |

Skip everything under `System.*`, `Microsoft.*`, `Mono.*`, `Xamarin.Forms.*`,
`netstandard` and `mscorlib`. That is the framework and it is enormous.

When only string dumps exist, work them properly rather than treating them as a
consolation prize. An `https://api.internal…` host tells you what the app talks
to. A `Server=…;Password=…` connection string is a finding on its own. And a
distinctive string is the `search_code` term that finds the code handling it.

---

## The .NET-specific classes

### Disabled TLS validation - check this first
```csharp
ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
handler.ServerCertificateCustomValidationCallback =
    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
```
Either line accepts every certificate, for every request the app makes. This is
the most common serious flaw in shipped Xamarin apps, because it is the standard
workaround people paste in to get past a development certificate and then forget.
Not the same as missing pinning - this is **NETWORK-01, High**, and it is a real
standalone vulnerability.

### Insecure storage
`Preferences.Set` (Xamarin.Essentials) and `Application.Current.Properties` are
plain unencrypted storage - the .NET wrappers around SharedPreferences and a
plist-style file. `SecureStorage` is the Keystore-backed one. A token in the
first two is the finding; the same token in `SecureStorage` is not.

### SQL injection
```csharp
var cmd = new SqliteCommand($"SELECT * FROM users WHERE name = '{name}'", conn);
conn.Query<User>("SELECT * FROM t WHERE id = " + id);
```
String interpolation (`$"…{x}…"`) into a `CommandText` is the .NET shape of this
bug and is easy to miss because it does not look like concatenation.

### Weak cryptography
`DESCryptoServiceProvider`, `TripleDESCryptoServiceProvider`, `MD5.Create()`,
`SHA1.Create()`, `CipherMode.ECB`, and a `byte[]` key or IV declared as a literal
array next to `Aes.Create()`. `Rfc2898DeriveBytes` with a low iteration count or
a hardcoded salt belongs here too.

### Unsafe deserialization
`BinaryFormatter` is remotely exploitable when it touches attacker-controlled
data and is deprecated outright in modern .NET. In Json.NET,
`TypeNameHandling.All` or `.Auto` lets the payload choose which type to
instantiate - the same class of bug.

### WebView
`Xamarin.Forms.WebView` and `Android.Webkit.WebView` both appear. Check
`JavascriptEnabled`, `AddJavascriptInterface`, and whether the loaded URL comes
from outside the app. `HybridWebView` and MAUI's `BlazorWebView` bind .NET
methods into JavaScript by design - enumerate what they expose. This is PLATFORM-04,
and it chains with deep links exactly as the Java version does.

### Native interop
`[DllImport("libfoo")]` crosses into native code that the managed review cannot
follow. Inspect the `.so` and say so rather than guessing.

### Reflection
`Activator.CreateInstance`, `Assembly.Load` and `Type.GetType` with a name from
configuration or input are how a .NET app reaches arbitrary code.

---

## Extraction caveat worth reporting honestly

Assemblies arrive in three shapes: plain PE, per-file LZ4 (`XALZ`), and one
packed `AssemblyStore` blob (`XABA`, sometimes disguised as
`lib/<abi>/libassemblies.*.blob.so`). The store's index layout has changed
across Xamarin versions. If the inventory looks short for the app's size, some
assemblies did not unpack - that is a coverage gap in the assessment, and saying
so plainly is worth more than a report that implies full coverage.
