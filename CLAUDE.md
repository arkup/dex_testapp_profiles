# ProfileTest

Test app for DEX Debugger (dexbgd).

Exercises all breakpoint profiles and xref features:
- **bp-crypto** - Cipher, SecretKeySpec, MessageDigest, Mac, KeyGenerator
- **bp-network** - URL.openConnection, HttpURLConnection, Socket
- **bp-exec** - Runtime.exec, ProcessBuilder.start
- **bp-loader** - DexClassLoader, InMemoryDexClassLoader, Class.forName, Method.invoke
- **bp-exfil** - TelephonyManager, ContentResolver.query, SmsManager
- **bp-detect** - File.exists, PackageManager, Build, SystemProperties, Debug
- **xref test** - hardcoded strings (URLs, passwords, API keys)

## Build & Deploy

```bash
gradlew assembleDebug
adb forward tcp:12345 localabstract:dexbgd  
adb install -r app/build/outputs/apk/debug/app-debug.apk
adb shell am start -n com.test.profiletest/.MainActivity
adb shell cmd activity attach-agent com.test.profiletest libart_jit_tracer.so
```
