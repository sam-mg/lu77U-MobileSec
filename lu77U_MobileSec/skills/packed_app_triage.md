# Packed and Hardened Apps - Recognising a Scan With Nothing In It

A commercially hardened APK ships a loader. The real classes are encrypted in an
asset or inside a native library and only exist in memory after the loader runs. The
decompiler produces a tree that parses cleanly, contains almost nothing, and yields no
findings.

That is the failure this skill exists to prevent: a packed app scanned to completion
and reported as clean. An empty result from a packed app is a coverage failure, and
it has to be reported as one.

## Recognising it in the first few reads

Any one of these on its own is weak. Two together is enough to act on.

**The application entry point is not the app's own class.** The manifest's
`android:name` on `<application>` points at a vendor stub rather than something under
the app's package:

```
search_code "android:name=\"[a-z]"
```

Stub names that are not the app: `com.stub.StubApp`, `com.secneo.apkwrapper.*`,
`s.h.e.l.l.*`, `com.tencent.StubShell`, and anything whose package bears no relation
to the package under scan.

**The class count is wrong for the app's size.** A 40 MB APK whose decompiled tree
holds a few dozen classes has not been decompiled - it has been unpacked to its
loader. Compare what the file tree shows against what the manifest declares: a
manifest listing twenty activities over a tree containing three of them is the
clearest single signal there is.

**A loader library sits in `lib/`.** These names are vendor-specific and stable
enough to identify:

| Library in `lib/` | Also look for |
|---|---|
| `libjiagu*.so` | `com.stub.StubApp` |
| `libshell*.so`, `libshella*.so` | `com.tencent.StubShell` |
| `libDexHelper.so`, `libdexjni.so` | `com.secneo.apkwrapper` |
| `libexec.so`, `libexecmain.so` | `s.h.e.l.l` package fragments |
| `libnesec.so` | NetEase loader classes |
| `libnaga*.so` | obfuscated single-letter loader package |
| `libapp-protect*.so`, `libDexProtect*.so` | generic protector naming |

**The declared components do not exist as classes.** Take three activity names out of
the manifest and search for each. If the manifest declares them and the tree has no
class for them, the classes are packed.

```
search_code "class MainActivity"
```

**An oversized opaque asset.** A multi-megabyte file in `assets/` or `res/raw/` with
no recognisable format, often named for the vendor, is the encrypted payload.

## What to do once you have identified it

Do not attempt to unpack. Unpacking a hardened app means running it and dumping DEX
from memory, which needs a rooted device, a hooked runtime and tooling this system
does not drive. Attempting it burns the step budget and produces nothing.

Do this instead, in order:

1. **Analyse what is genuinely there.** The manifest is not packed. Neither are the
   resources, the network security configuration, the declared components, the
   permissions or the native libraries. A packed app can still have a debuggable
   build, a cleartext policy, an exported component with no permission, or a secret
   in `strings.xml`. Those findings are real and they still count.
2. **Name the protection as an observation.** Which vendor, and what you matched on.
   This is informational: shipping a packer is not a vulnerability, and reporting it
   as one is padding.
3. **State the coverage limit explicitly.** The application's own code was not
   available for review. Say which parts of the analysis that invalidates - every
   code-level class, so injection, crypto, storage and authentication logic were not
   examined at all.
4. **Do not report the absence of findings as their absence.** "No hardcoded secrets
   found" is false when the code holding them was never decompiled. The correct
   statement is that the check could not be performed.

## The reporting distinction that matters

| Situation | What the report should say |
|---|---|
| App scanned, code present, nothing found | No issues of this class were identified |
| App packed, code absent | This class of issue could not be assessed; the application code was not available |

Collapsing the second into the first is the single most misleading thing a scan of a
hardened app can do, because it converts "we could not look" into "we looked and it
was fine".

## Packing is not obfuscation

They look similar in a file tree and they are not the same problem.

Obfuscated code is *present* - renamed to single letters, control flow mangled, strings
encrypted, but there and analysable with effort. Packed code is *absent* until
runtime. If classes exist with meaningless names, that is obfuscation and the
obfuscation guidance applies. If the classes do not exist at all, that is packing and
this one does.

An app can be both, and usually is: unpack it and you get obfuscated code.

## A note on partial packing

Some products pack only selected classes and leave the rest. The tree then looks
mostly normal with specific gaps, which is harder to spot than the all-or-nothing
case. Watch for a class that is referenced everywhere and defined nowhere - a call to
`SecurityManager.check()` across a dozen files with no `SecurityManager` in the tree
means that class specifically was protected. Report the gap where it lands rather
than treating the whole scan as blocked.
