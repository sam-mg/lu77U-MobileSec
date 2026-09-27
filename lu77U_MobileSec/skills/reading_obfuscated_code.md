# Working in Obfuscated Code

Almost every app worth scanning is obfuscated. Class and method names are gone,
control flow is rearranged, and strings may be encrypted. That does not make the
app unreadable - it makes *names* unreadable, and names were never the evidence.

The failure mode this skill exists to prevent: reading three meaningless files,
concluding the app is opaque, and reporting only the manifest. The most serious
finding in an obfuscated app is usually sitting in a class called `a` or
`C0900k`.

---

## What survives obfuscation

Obfuscators rename what they can prove is safe to rename. Everything below is
untouched, and all of it is evidence:

| Survives | Why | What it gives you |
|---|---|---|
| Framework API calls | Renaming `loadUrl` would break the platform | Every sink in `android_analysis` |
| Annotations | Read reflectively at runtime | `@JavascriptInterface`, `@SerializedName`, DI graphs |
| String literals | Only removed by a separate string-encryption pass | URLs, keys, SQL, error text, log tags |
| Manifest component names | Must resolve to real classes | Your entry points |
| Reflection targets | Looked up by name at runtime | Whatever the app reaches dynamically |
| Native symbol names | Exported for JNI linkage | `Java_com_app_Foo_bar` tells you the pre-obfuscation package |
| Resource names | Referenced from XML | Layouts, string keys |

So: **search by API call and annotation, never by class name.** A search for
`addJavascriptInterface` finds the bridge in an app where nothing else is
legible.

---

## Getting oriented

1. **Start from the manifest.** Component names in it are real class names and
   they resolve. That is your list of externally reachable entry points, and it
   is unaffected by obfuscation.
2. **Search the sink table**, not the file tree. Each hit is a candidate; the
   class name it lives in is irrelevant.
3. **Pivot on strings.** A distinctive literal - an endpoint path, an error
   message, a preference key - is a search term that finds every class touching
   that feature. This is the single most effective technique in an obfuscated
   app: find one string you understand, then find everything referencing it.
4. **Follow native symbols back.** `Java_com_target_crypto_KeyStore_decrypt` in a
   `.so` names a class the Java side no longer names, and tells you where the
   interesting code went.

---

## Recognising the transformations

**Renaming.** `a.b.c`, single-letter methods, numeric suffixes (`C0900k`).
Nothing to do about it - work by call signature.

**Overload packing.** Many unrelated methods share a name, distinguished only by
signature. When you trace a call, match the argument types, not the name.

**Synthetic accessors.** `access$000`-style bridges between inner and outer
classes. They are compiler output; step through them.

**String encryption.** Literals replaced by calls like `a.b("x8f2...")`. The
decrypt routine is in the app and is usually one small class used everywhere -
find one call site, read the routine, and you know the scheme for the whole app.
If it is a simple XOR or a table substitution you can often decode by hand.
If you cannot, say so: an encrypted-strings app is a coverage gap, and stating
it plainly is worth more than pretending the strings were not there.

**Control-flow flattening.** Method bodies become a `while` loop around a
`switch` on a state variable, with the real logic scattered across cases. Read
the cases as a graph rather than top to bottom, and use the constants assigned to
the state variable to order them.

**Reflection instead of direct calls.** `Class.forName` with a name assembled at
runtime hides the callee from static analysis. Whatever assembles that name is
where to read; if it comes from a server response or an Intent extra, that is a
finding in its own right (`CODE-02`).

**Packing.** A tiny `classes.dex` next to a large `.so` or an encrypted asset
means the real DEX is loaded at runtime and is not in the tree you were given.
Look for `DexClassLoader`, `InMemoryDexClassLoader`, or a decrypt-then-load in
`attachBaseContext`. You cannot recover the payload statically - report the
packer and the coverage gap, and hand it to the dynamic phase.

---

## Kotlin decompiles noisily

Most of what looks wrong in decompiled Kotlin is the compiler, not the developer.

- `Intrinsics.checkNotNullParameter(x, "x")` at the top of every method - null
  checks, ignore them.
- `WhenMappings` classes with integer arrays - `when` over an enum.
- Methods ending `$app_release`, `$default`, or with `$this$` receivers -
  internal visibility, default arguments, extension functions.
- `suspend` functions become state machines: a `label` field, a `switch`, and
  the real body split across cases. `Result.Companion.constructor-impl` around
  it is exception plumbing.
- Data classes generate `component1()`, `copy()`, `hashCode()` - never worth
  reading.

None of that is a finding. Reporting decompiler artefacts as logic bugs is how a
report loses the reader.

---

## Saying you could not see something

A coverage gap stated plainly is a useful result. A coverage gap dressed up as
"no issues found" is a false negative with confidence attached.

Say which of these applies, and where:

- The DEX is packed and the real code loads at runtime.
- Strings are encrypted and the routine could not be resolved.
- The path crosses into native code that static review cannot follow.
- The class did not decompile, or decompiled to fragments.
- A split APK or dynamic feature module was not present in what was scanned.

Each of those is a sentence in the report and, where the dynamic phase can
settle it, a specific thing to try on a device.
