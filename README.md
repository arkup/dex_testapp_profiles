# ProfileTest

Test app for [dexbgd](https://github.com/arkup/dexbgd) — an Android DEX debugger/tracer. Exercises every breakpoint profile and xref feature so you can verify the agent is firing correctly before using it on real targets.

## What It Tests

Each button in the UI triggers a specific API category:

| Profile | APIs exercised |
|---------|---------------|
| **bp-crypto** | `Cipher`, `SecretKeySpec`, `IvParameterSpec`, `MessageDigest`, `Mac`, `KeyGenerator` |
| **bp-network** | `URL.openConnection`, `HttpURLConnection`, `Socket` |
| **bp-exec** | `Runtime.exec`, `ProcessBuilder.start` |
| **bp-loader** | `DexClassLoader`, `InMemoryDexClassLoader`, `Class.forName`, `Method.invoke` |
| **bp-exfil** | `TelephonyManager.getDeviceId`, `ContentResolver.query`, `SmsManager` |
| **bp-detect** | `File.exists` (su paths), `PackageManager.getPackageInfo` (root/hook pkgs), `Build` fields, `SystemProperties`, `Debug.isDebuggerConnected` |
| **xref** | Hardcoded C2 URL, exfil endpoint, API key, password, AES key string, DB path |
| **jni monitor** | `NativeProtector` — 4 methods bound via `RegisterNatives` in `JNI_OnLoad` (no `Java_...` symbols) |

The **Run All** button fires every category in sequence.

## Setup

### 1. Build the agent

Build `libart_jit_tracer.so` from the dexbgd agent directory, then copy it into the app:

```
cp agent/build/libart_jit_tracer.so app/src/main/jniLibs/arm64-v8a/
```

### 2. Build and install the APK

```bash
gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

### 3. Launch and attach the agent

```bash
# easiest is to start dexbgd server and use "launch" command
.\dexbgd\server>cargo run

# then type the following command line:
launch com.test.profiletest

# done set breakpoint
# bp MainActivity.testDetect

# or set breakpoint profiles e.g.
bp-detect

```

Alternatively, you can type all the `launch` commands manually:

```bash
# Forward the dexbgd control socket
adb forward tcp:12345 localabstract:dexbgd

# Start the app
adb shell am start -n com.test.profiletest/.MainActivity

# Attach the JIT tracer agent
adb shell cmd activity attach-agent com.test.profiletest libart_jit_tracer.so
```

```bash
# start dexbgd server
cargo run

# press F1 or type
connect

#set breakpoint profiles e.g. bp-crypto or ..
bp MainActivity testDetect

```

The status bar in the app will read **"Ready. Attach agent, set breakpoints, then press buttons."** once the activity is running.

### 4. Set breakpoints, then press buttons

Use dexbgd to set breakpoints for the profile you want to test, then tap the corresponding button. Check `adb logcat -s ProfileTest` to see what each test actually calls.

## Permissions

The app requests these dangerous permissions at startup (required for exfil/detect tests):

- `READ_PHONE_STATE` — `TelephonyManager.getDeviceId`
- `READ_CONTACTS` — `ContentResolver.query` on contacts
- `SEND_SMS` — `SmsManager` reference
- `ACCESS_FINE_LOCATION`

Grant them when prompted, or the relevant tests will log a `SecurityException` and continue.

## Root Detection Output

The **bp-detect** button (and Run All) displays a result label:

- `Root: not detected (0)` — clean environment
- `Root: DETECTED (1)` — su binary, root/hook package, test-keys build, or debuggable system property found

## JNI Monitor Test

The **Native Protector** button exercises the `jni monitor` / `jni redirect` features introduced in dexbgd.

`libnative_protector.so` registers its methods via `RegisterNatives` in `JNI_OnLoad` rather than exporting `Java_...` symbols. This means:

- `readelf -s libnative_protector.so` shows no Java binding
- jadx/apktool cannot statically resolve which native function backs each method
- `jni monitor` in dexbgd captures the binding at runtime

**Methods registered:**

| Java method | Signature | Default return |
|---|---|---|
| `isProtected()` | `()Z` | `true` |
| `checkIntegrity()` | `()I` | `1` |
| `getLicenseKey()` | `()Ljava/lang/String;` | `"NTV-XXXX-PRO-2024-AABBCCDD"` |
| `isDebuggerPresent()` | `()Z` | `false` |

**Workflow:**

```
# Right-click anywhere in the JNI tab -> "Start monitoring"
# (or type the command)
jni monitor                    <- start capturing RegisterNatives

[press "Native Protector" button]
                               <- library loads, JNI_OnLoad fires
                               <- 4 bindings appear in JNI tab:
  libnative_protector.so+0x..  boolean NativeProtector.isProtected()
  libnative_protector.so+0x..  int NativeProtector.checkIntegrity()
  libnative_protector.so+0x..  String NativeProtector.getLicenseKey()
  libnative_protector.so+0x..  boolean NativeProtector.isDebuggerPresent()

# Right-click any binding -> shows function name + Redirect / Restore options
# (or use commands):

# Redirect by address (copy from JNI tab):
jni redirect libnative_protector.so+0xXXXX block    <- always return false / 0 / null
jni redirect libnative_protector.so+0xXXXX true     <- always return true / 1
jni redirect libnative_protector.so+0xXXXX false    <- always return false / 0
jni redirect libnative_protector.so+0xXXXX spoof 1  <- return specific integer value

# Or redirect by class sig (use short method name, no Java_ prefix):
jni redirect Lcom/test/profiletest/NativeProtector; isProtected ()Z block
jni redirect Lcom/test/profiletest/NativeProtector; checkIntegrity ()I block
jni redirect Lcom/test/profiletest/NativeProtector; checkIntegrity ()I spoof 1

[press button again]           <- result shows false / 0 instead of true / 1

# Restore original pointer:
jni restore libnative_protector.so+0xXXXX
jni restore Lcom/test/profiletest/NativeProtector; checkIntegrity ()I
```

**Action reference:**

| Action | Effect |
|--------|--------|
| `block` | Stub returns zero/false/null for any return type |
| `true` | Returns `true` (boolean) or `1` (int/long) |
| `false` | Returns `false` (boolean) or `0` (int/long) |
| `spoof N` | Returns the integer `N` (cast to the method's return type) |

**Right-click shortcut:** In the JNI tab, right-click any binding to get a context menu showing the function name with Redirect / Restore options — no typing required. Right-click on an empty area to start/stop monitoring.

## Break-on-Access Watchpoints

The `ba` command sets a field watchpoint that fires when a field is read or written,
regardless of which method or thread does it. Suspends the thread and shows stack/locals/dis
on hit, same UX as a breakpoint.

```
ba Lcom/test/profiletest/MainActivity; detectResult       # break on read or write
ba w Lcom/test/profiletest/MainActivity; detectResult     # write only
ba r Lcom/test/profiletest/MainActivity; jniResult        # read only

bad 1    # delete watchpoint #1
bal      # list all active watchpoints
```

**Suggested test targets:**

| Field | Mode | What it shows |
|-------|------|---------------|
| `detectResult` | `w` | Fires when root detection result is written — lands at the exact bytecode that sets it, with full call stack from the detection logic |
| `jniResult` | `w` | Written from the background thread running `testNative()` — demonstrates cross-thread watchpoint firing |
| `status` | `w` | Written in `onCreate` — fires immediately on startup |

**Note:** `static final String` constants (like `AES_KEY_STRING`, `API_KEY`) are inlined
by d8 as `const-string` bytecodes at every use site, so read watchpoints on them will
never fire. Use `dis` to confirm — you will see `const-string` rather than `sget-object`.

## Notes

- Network tests hit `httpbin.org/get`; the socket test intentionally fails (connects to `127.0.0.1:9999`).
- Loader tests write a minimal embedded DEX to `getFilesDir()/payload.dex`, load it via `DexClassLoader`, then load the same bytes from memory via `InMemoryDexClassLoader`. The DEX contains a single class `com.test.payload.DynamicPayload` with a static `getMessage()` method.
- Xref strings are `private static final` constants — they end up in the DEX constant pool and are findable with `xref` / `xref-bp` commands without running the app.
