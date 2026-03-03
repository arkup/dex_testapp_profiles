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

## Notes

- Network tests hit `httpbin.org/get`; the socket test intentionally fails (connects to `127.0.0.1:9999`).
- Loader tests write a minimal embedded DEX to `getFilesDir()/payload.dex`, load it via `DexClassLoader`, then load the same bytes from memory via `InMemoryDexClassLoader`. The DEX contains a single class `com.test.payload.DynamicPayload` with a static `getMessage()` method.
- Xref strings are `private static final` constants — they end up in the DEX constant pool and are findable with `xref` / `xref-bp` commands without running the app.
