# Native Library Analysis - Finding the Logic That Left Java

When an app's interesting logic is in a `.so`, the decompiled Java is a shell: a
`native` method declaration, a `System.loadLibrary` call, and nothing else to read.
This skill is about establishing *whether* that is the case, naming the entry points
precisely enough for a report, and knowing where your evidence stops.

## What this system actually gives you

`inspect_native <path>` returns, in this order:

1. **Signals** - exported `Java_*` entry points, risky imports (`strcpy`, `system`,
   ...), embedded endpoints and credential candidates, from the symbols and strings.
2. **Decompiled C**, only when Ghidra is configured - every function of the library,
   JNI entry points first, then functions that call a risky import, then the rest.
   Calls through the JNI function table are annotated, so
   `(**(code **)(*param_1 + 0x548))(param_1,param_3,0)  /* JNIEnv->GetStringUTFChars */`
   reads as "take the Java string argument as a C string".
3. **The dynamic symbol table** (`objdump -T`).

A large library is paged like `read_file`: call `inspect_native` on the same path again
to continue, or pass `start_line`.

If the output says `## Decompiled code (unavailable: ...)`, you have only the symbols
and strings. Then do not describe what a function does - you did not read it. When
the decompiled C is present, you did read it, and you can and should trace data flow
through it.

Decompiled C is reconstructed: `param_1`, `local_48`, `iVar1` and the types are the
decompiler's inventions. Control flow, constants, string literals, buffer sizes and
call targets come from the binary and are citable. In a finding, put the line number
from the `inspect_native` view in `"line"`, exactly as you would for `read_file`, and
name the function (or its `FUN_<address>` placeholder in a stripped library) and its
address in the description. An address in `"line"` is not a line number.

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
`JNI_OnLoad` and little else. With decompiled C, read `JNI_OnLoad`: the call
annotated `JNIEnv->RegisterNatives` takes the table, and its entries name each Java
method and the `FUN_<address>` that implements it.

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

## Reading the decompiled JNI functions

In a `Java_*` function the parameters are fixed by the JNI calling convention:
`param_1` is the `JNIEnv*`, `param_2` the `jobject`/`jclass`, and `param_3` onwards are
the Java method's own arguments, in order. That is what lets you follow Java input:

```c
__src = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);  /* JNIEnv->GetStringUTFChars */
strcpy(local_48,__src);          /* local_48 is char[64] */
```

Here the first Java argument is copied, unbounded, into a 64-byte stack buffer: a
stack buffer overflow driven by whatever the Java caller passes. Two things make this
a finding rather than a lead - the source is a Java argument, and the destination has
a fixed size smaller than what the caller can supply. Name both, and find the Java
call site that feeds the argument (usually a UI field or an intent extra). Class it
`CODE-05` (memory corruption), not `CODE-02`.

```c
__s2 = (char *)(**(code **)(*param_1 + 0x548))(param_1,param_3,0);  /* JNIEnv->GetStringUTFChars */
iVar1 = strcmp("Xk9-pr0-l1c3nse",__s2);
return iVar1 == 0;
```

Here a Java argument is compared against a literal and the result returned: a secret
hardcoded in native code. Moving a key into a `.so` hides it from the decompiled Java,
not from anyone with a decompiler. Report the literal, the function, and the Java
method that calls it.

Other patterns worth the same treatment:

```
strcpy  strcat  sprintf  vsprintf  gets        # no bounds, caller-supplied length
system  popen  execl  execve                   # command execution - check what builds the string
memcpy  alloca                                 # unbounded when the length is attacker-derived
strcmp/strncmp/memcmp against a literal        # hardcoded credential or licence check
fopen/open on a path built from input          # path traversal in native code
```

## When there is no decompiled code

An import is not a bug. Without the decompiled C, it is a reason to trace whether
attacker-controlled data reaches that call - which you usually cannot finish from the
symbol table. Report the import alongside the reachable entry point and say the
data-flow step was not performed, rather than asserting an overflow you did not
demonstrate.

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
- the function and address you read, and the decompiled lines that show the bug
  (the copy into a fixed-size buffer, the comparison against a literal)
- which registration model it uses, and therefore what you could and could not enumerate
- the Java call site that reaches it, and which argument carries the input
- whether reachability was demonstrated at runtime or only inferred statically

A finding that stops at "the app contains native code" is not a finding. Neither is
one that describes behaviour inside a function nobody decompiled - if the decompiled
code is unavailable and the analysis needs it, recommend decompilation as a follow-up
and say why, instead of guessing at what the function does.
