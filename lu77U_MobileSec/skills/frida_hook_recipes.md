# Frida Hook Recipes - Extracting Values at Runtime

Concrete hook patterns for observing what an app does with data. The strategy - which
finding to prove, what counts as evidence, when not to hook at all - is in the
offensive testing guidance; this is the reference for writing the hook itself once
you have decided what to watch.

These are all **observation** hooks: log the value, return the original. Changing a
return value is a separate decision, and you make it only when the finding is
specifically that the check can be defeated.

## The shape every hook shares

```javascript
Java.perform(() => {
  const Target = Java.use('com.vendor.app.Thing');
  Target.method.implementation = function (arg) {
    const out = this.method(arg);          // call through first
    send(`Thing.method(${arg}) -> ${out}`); // then report
    return out;                             // and hand back what it really returned
  };
});
```

Call through before reporting. A hook that logs and then forgets to invoke the
original silently changes app behaviour, and you will spend the rest of the session
debugging the app you broke.

## Overloads

`Java.use` gives you a method object that throws if the method is overloaded and you
did not say which one. Name the signature with `.overload()`:

```javascript
const C = Java.use('javax.crypto.Cipher');
C.doFinal.overload('[B').implementation = function (b) { /* ... */ };
```

If you do not know the signatures, enumerate them once rather than guessing:

```javascript
Java.use('com.vendor.app.Thing').class.getDeclaredMethods()
  .forEach(m => send(m.toString()));
```

## Cryptography - recovering keys, IVs and plaintext

The key and IV are set on the `Cipher` before use, so hook `init` for the material
and `doFinal` for the data.

```javascript
Java.perform(() => {
  const Cipher = Java.use('javax.crypto.Cipher');
  const Key = Java.use('javax.crypto.spec.SecretKeySpec');
  const IvSpec = Java.use('javax.crypto.spec.IvParameterSpec');

  Key.$init.overload('[B', 'java.lang.String').implementation = function (raw, alg) {
    send(`SecretKeySpec ${alg} key=${bytesToHex(raw)}`);
    return this.$init(raw, alg);
  };

  IvSpec.$init.overload('[B').implementation = function (raw) {
    send(`IV=${bytesToHex(raw)}`);
    return this.$init(raw);
  };

  Cipher.doFinal.overload('[B').implementation = function (input) {
    const out = this.doFinal(input);
    send(`Cipher(${this.getAlgorithm()}) in=${bytesToHex(input)} out=${bytesToHex(out)}`);
    return out;
  };
});
```

`this.getAlgorithm()` on the `Cipher` tells you the transformation actually in use,
which is how you confirm an ECB mode or a hardcoded key that the static finding only
inferred.

For digests, the same idea against `MessageDigest.digest`, and for message
authentication against `javax.crypto.Mac.doFinal` - hook `Mac.init` for the key.

## HTTP - seeing the request as it goes out

OkHttp backs most Android networking, including Retrofit, so hooking it once covers
both. Take the request at construction rather than at the socket:

```javascript
Java.perform(() => {
  const Builder = Java.use('okhttp3.Request$Builder');
  Builder.build.implementation = function () {
    const req = this.build();
    send(`${req.method()} ${req.url()}`);
    const h = req.headers();
    for (let i = 0; i < h.size(); i++) send(`  ${h.name(i)}: ${h.value(i)}`);
    return req;
  };
});
```

This is how you confirm a token travels in a header, an API key rides in a query
string, or a request carries no integrity signature at all.

For the legacy stack, hook `java.net.URL.openConnection`. For React Native, the same
OkHttp hook works because the bridge uses it underneath.

## WebView - what actually gets loaded and what is exposed to it

```javascript
Java.perform(() => {
  const WV = Java.use('android.webkit.WebView');

  WV.loadUrl.overload('java.lang.String').implementation = function (url) {
    send(`loadUrl: ${url}`);
    return this.loadUrl(url);
  };

  WV.addJavascriptInterface.implementation = function (obj, name) {
    send(`bridge "${name}" -> ${obj.$className}`);
    return this.addJavascriptInterface(obj, name);
  };
});
```

The bridge hook gives you the object's real class at runtime, which is the reliable
way to find the methods exposed to page script when the static side only showed the
registration call.

## Local storage - preferences and databases

```javascript
Java.perform(() => {
  const Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
  Editor.putString.implementation = function (k, v) {
    send(`prefs put ${k}=${v}`);
    return this.putString(k, v);
  };

  const DB = Java.use('android.database.sqlite.SQLiteDatabase');
  DB.execSQL.overload('java.lang.String').implementation = function (sql) {
    send(`execSQL: ${sql}`);
    return this.execSQL(sql);
  };
  DB.rawQuery.overload('java.lang.String', '[Ljava.lang.String;')
    .implementation = function (sql, args) {
      send(`rawQuery: ${sql} args=${args}`);
      return this.rawQuery(sql, args);
    };
});
```

Hooking the writes is what turns "this value is stored in plaintext" from a static
claim into an observed one. For injection, the `rawQuery` hook shows you the fully
assembled statement - if attacker-controlled text appears inside the SQL string
rather than in the argument array, the finding is confirmed at that moment.

## Finding the class when the name is obfuscated

When the static side gave you a single-letter class, enumerate what is loaded and
filter:

```javascript
Java.perform(() => {
  Java.enumerateLoadedClasses({
    onMatch(name) { if (name.includes('com.vendor.app')) send(name); },
    onComplete() {},
  });
});
```

Under multiple class loaders - which every packed app and many plugin frameworks use
- `Java.use` may not find a class that plainly exists. Switch loaders first:

```javascript
Java.perform(() => {
  Java.enumerateClassLoaders({
    onMatch(loader) {
      try {
        loader.loadClass('com.vendor.app.Security');
        Java.classFactory.loader = loader;   // subsequent Java.use resolves here
        send(`using loader ${loader}`);
      } catch (e) {}
    },
    onComplete() {},
  });
});
```

## Where the call came from

When a method fires and you need to know who called it, print the Java stack from
inside the hook:

```javascript
function stack() {
  return Java.use('android.util.Log')
    .getStackTraceString(Java.use('java.lang.Exception').$new());
}
```

This is how you attribute a crypto call or a network request to the feature that
triggered it, which is usually the difference between a finding a developer can act
on and one they cannot locate.

## Byte arrays

Java byte arrays arrive as JavaScript arrays of signed bytes, so print them
deliberately rather than relying on string coercion:

```javascript
function bytesToHex(a) {
  return Array.from(a, b => ((b & 0xff) + 0x100).toString(16).slice(1)).join('');
}
function bytesToUtf8(a) {
  return Java.use('java.lang.String').$new(a);
}
```

Try both on key material. A key that renders as readable text was derived from a
string constant, which usually means it is in the code you already have.

## Flutter apps - the logic is not in Java

In a Flutter app `Java.use` only reaches the platform layer: plugin code, channel
handlers, root and integrity checks. The app's own logic is compiled Dart in
`libapp.so` and is hooked by offset - the `** addr: 0x...` value Blutter prints above
each function, relative to `libapp.so` with no image base to subtract:

```javascript
function onLibappLoaded() {                 // inside Blutter's blutter_frida.js template
  Interceptor.attach(libapp.add(0x3a0d14), {
    onEnter() { init(this.context); },
    onLeave(retval) {
      const [, cls, value] = getTaggedObjectValue(retval);   // decodes Dart objects
      send(`${cls.name} = ${JSON.stringify(value)}`);
    }
  });
}
```

- Use Blutter's `blutter_frida.js` as the base; it decodes Dart strings, lists and
  objects for that exact Dart version. Do not hand-decode tagged pointers.
- Dart `true`/`false` are `NullReg + 0x20` / `NullReg + 0x30`.
- An `async` function returns a `Future`; hook the caller at the instruction right
  after its `Await()`, where `x0` holds the resolved value.
- Spawn (`-f`) and poll for `libapp.so` every 100 ms: checks in `initState()` run once,
  before a slow hook is installed.
- Dart HTTP ignores the device proxy and the Android CA store - see
  `flutter_reverse_engineering` for frida-flutterproxy and the NVISO script before
  concluding anything from an empty proxy.

## React Native apps - the JS runtime and its native modules

In a React Native app `Java.use` reaches the native modules and React Native's own
Java (networking, blobs, the bridge); the app's logic is JavaScript in Hermes or JSC.

- Observe traffic below the JS layer by hooking
  `com.facebook.react.modules.network.ResponseUtil.onResponseReceived` /
  `onDataReceived` - no proxy needed, and pinning does not hide it.
- Call a native module directly: `Java.choose('<module class>')`, then invoke the
  `@ReactMethod` with a `Promise` built by `Java.registerClass` (implement every
  `reject` overload).
- On the old bridge, run your own JS inside the app by hooking
  `com.facebook.react.bridge.CatalystInstanceImpl.loadScriptFromAssets` and calling
  `loadScriptFromFile` on a payload after the original; `require` is unavailable in a
  Frida script itself.

`react_native_reverse_engineering` covers bundle redirection, WebView bridges and
bytecode patching.

## Keeping the output usable

Hook the one class the finding names. A broad `frida-trace` pattern over every crypto
or network method on a real app produces thousands of lines per screen, costs step
budget to read, and buries the single call that mattered. Start narrow, widen only
when the narrow hook does not fire - and if it does not fire, that absence is itself
worth recording, because it means the code path you were told about was not reached.
