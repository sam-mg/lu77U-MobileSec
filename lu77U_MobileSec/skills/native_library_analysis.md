# Native Library Analysis - Finding the Logic That Left Java

When an app's interesting logic is in a `.so`, the decompiled Java is a shell: a
`native` method declaration, a `System.loadLibrary` call, and nothing else to read.
This skill is about establishing *whether* that is the case, naming the entry points
precisely enough for a report, and knowing where your evidence stops.

## What this system actually gives you

`inspect_native <path>` runs `objdump -T` and returns the **dynamic symbol table**.
That is exported symbol names only - no strings, no disassembly, no decompilation.
Everything below works from the symbol table, the decompiled Java that calls into it,
and (in dynamic verification) a Frida hook on a resolved export.

Do not claim you read native code. You read its symbol table.

## Two registration models, and why the symbol table lies

A Java `native` method reaches C in one of two ways, and only one of them is visible
to `objdump`.

**Static registration** - the symbol name encodes the Java path, so it appears in the
symbol table and you can match it to a class by reading it:

```
Java_com_vendor_app_Security_sign
```

**Dynamic registration** - `JNI_OnLoad` calls `RegisterNatives` with a table of
`{name, signature, function_pointer}`. The implementation functions are usually
local, often stripped, and named nothing in particular. `objdump -T` shows you
`JNI_OnLoad` and little else.

The consequence matters more than the mechanism:

> A `.so` whose symbol table exports `JNI_OnLoad` but few or no `Java_*` symbols is
> not a library with no native entry points. It is almost certainly a library that
> registers them dynamically, and the symbol table cannot enumerate them.

Absence of `Java_*` exports is a limit on your visibility, not evidence of a small
native surface. Say so in those words rather than reporting the library as
uninteresting.

## Name mangling, for matching a symbol to a class

Static symbols are mangled predictably. You need this to match a symbol back to the
Java that declares it:

| Java | Symbol fragment |
|---|---|
| package/class separator `.` | `_` |
| a literal `_` in an identifier | `_1` |
| `;` in a type signature | `_2` |
| `[` in a type signature | `_3` |
| overloaded method | base name, then `__`, then the argument signature mangled |

So `com.vendor.app.Security.sign(String)` is `Java_com_vendor_app_Security_sign`, and
if it is overloaded, `Java_com_vendor_app_Security_sign__Ljava_lang_String_2`.

## Establishing the boundary from the Java side

Start in Java, not in the library. These searches map the whole native surface that
the app itself declares, including the dynamically registered methods `objdump`
cannot show you:

```
search_code "native "
search_code "System\.loadLibrary"
search_code "System\.load\("
```

For each hit, record the declaring class, the method name, its parameters and its
return type. That list is the real native surface. Cross-reference it against the
symbol table: anything declared in Java but absent from the exports is
dynamically registered, which is itself worth stating.

`System.load` taking a path rather than a library name is worth a second look - it
means the library is loaded from somewhere the app chose at runtime, which raises
where that file came from and whether anything else can write to it.

## When the logic really is in native, and how you can tell

Treat these as escalation signals rather than conclusions:

- A signing, encryption, licence or attestation method is declared `native` and the
  Java side only marshals arguments into it.
- The Java class that would hold the check contains a `native` declaration and a
  `loadLibrary` call and nothing else of substance.
- A method named for a security decision returns a value the Java never computes.
- The imports on the library name a crypto implementation the Java never calls.

When several of these line up, the honest finding is "the check is implemented in
`lib<name>.so` and is not analysable from the decompiled Java" - which is a real,
reportable coverage statement. It is not a vulnerability by itself.

## Reading the import side for memory-safety risk

`objdump -T` also lists imported symbols. The classic memory-unsafe and
command-executing libc calls are worth noting when they appear in a library that
handles untrusted input:

```
strcpy  strcat  sprintf  vsprintf  gets        # no bounds, caller-supplied length
system  popen  execl  execve                   # command execution
memcpy  alloca                                 # unbounded when the length is attacker-derived
```

An import is not a bug. It is a reason to trace whether attacker-controlled data
reaches that call - which, without disassembly, you usually cannot finish. Report
the import alongside the reachable entry point and say the data-flow step was not
performed, rather than asserting an overflow you did not demonstrate.

## Proving reachability at runtime

In dynamic verification you can show a native entry point is actually hit. This works
for statically registered exports, where you have a name to resolve:

```javascript
Interceptor.attach(Module.getExportByName('libsecurity.so', 'Java_com_vendor_app_Security_sign'), {
  onEnter(args) { send('native sign() reached'); },
});
```

Then trigger the screen that calls it with `adb am start -n <pkg>/<Activity>`, or call
the Java wrapper directly from a `Java.perform` block, and observe the hook fire.

For a dynamically registered method there is no export to resolve by name, so hook
the **Java** wrapper instead and record that the native implementation was not
addressable by symbol. That is a weaker but honest piece of evidence.

## What to write down

A defensible native finding names:

- the library, by the path it actually has in the APK (`lib/arm64-v8a/lib<name>.so`)
- the entry point, as either a resolved export or a Java `native` declaration
- which registration model it uses, and therefore what you could and could not enumerate
- the Java call site that reaches it
- whether reachability was demonstrated at runtime or only inferred statically

A finding that stops at "the app contains native code" is not a finding. Neither is
one that describes behaviour inside a function nobody disassembled - if the analysis
needs disassembly, recommend it as a follow-up and say why, instead of guessing at
what the function does.
