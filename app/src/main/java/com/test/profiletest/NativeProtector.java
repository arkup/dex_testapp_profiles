package com.test.profiletest;

/**
 * Simulated native protector library.
 *
 * Methods are NOT exported as Java_com_test_profiletest_NativeProtector_xxx symbols.
 * They are bound via RegisterNatives in JNI_OnLoad — the standard technique
 * real protectors use so the Java<->native mapping is invisible to jadx/apktool.
 *
 * dexbgd usage:
 *   jni monitor                 <- start capturing RegisterNatives
 *   [press JNI Protector button]
 *   5                           <- switch to JNI tab, see all 4 bindings
 *   jni redirect libnative_protector.so+0xXXXX block    <- or by class sig
 *   [press button again]        <- see changed return values
 */
public class NativeProtector {
    static {
        System.loadLibrary("native_protector");
    }

    /** Returns true if the device/app passes integrity checks. */
    public native boolean isProtected();

    /** Returns 1 if license is valid, 0 if tampered/expired. */
    public native int checkIntegrity();

    /** Returns a key decrypted in native code (invisible in DEX constant pool). */
    public native String getLicenseKey();

    /** Returns true if a debugger is attached (native ptrace check). */
    public native boolean isDebuggerPresent();
}
