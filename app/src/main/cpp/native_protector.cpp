#include <jni.h>
#include <android/log.h>

#define TAG "NativeProtector"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// Native implementations.
//
// NOTE: These are NOT named Java_com_test_profiletest_NativeProtector_xxx.
// They are registered explicitly via RegisterNatives in JNI_OnLoad — the
// same technique real protectors use to make the Java<->native mapping
// invisible to static analysis and hard to find via symbol tables.
//
// dexbgd: run 'jni monitor' before the app loads, then press the JNI button
// to see all four bindings appear in the JNI tab.  Use 'jni redirect' to
// change return values and press the button again to see the effect.
// ---------------------------------------------------------------------------

static jboolean native_isProtected(JNIEnv*, jobject) {
    // Simulates a native integrity guard.
    // Real protectors check: /proc/self/maps for Frida, ptrace status,
    // certificate hash, SO integrity, etc.
    LOGI("isProtected() -> true");
    return JNI_TRUE;
}

static jint native_checkIntegrity(JNIEnv*, jobject) {
    // Simulates a native license/integrity check.
    // 1 = valid/licensed, 0 = tampered/unlicensed.
    LOGI("checkIntegrity() -> 1");
    return 1;
}

static jstring native_getLicenseKey(JNIEnv* env, jobject) {
    // Simulates a key that is decrypted in native code and returned to Java.
    // In real protectors this would be XOR'd, AES-decrypted, or derived from
    // device fingerprint — invisible in the DEX constant pool.
    const char* key = "NTV-XXXX-PRO-2024-AABBCCDD";
    LOGI("getLicenseKey() -> %s", key);
    return env->NewStringUTF(key);
}

static jboolean native_isDebuggerPresent(JNIEnv*, jobject) {
    // Simulates a native debugger detection check.
    // Real version would check /proc/self/status TracerPid field.
    LOGI("isDebuggerPresent() -> false");
    return JNI_FALSE;
}

// ---------------------------------------------------------------------------
// Explicit RegisterNatives in JNI_OnLoad (protector-style registration)
// ---------------------------------------------------------------------------

static JNINativeMethod g_methods[] = {
    { "isProtected",       "()Z",                  (void*)native_isProtected       },
    { "checkIntegrity",    "()I",                  (void*)native_checkIntegrity    },
    { "getLicenseKey",     "()Ljava/lang/String;", (void*)native_getLicenseKey     },
    { "isDebuggerPresent", "()Z",                  (void*)native_isDebuggerPresent },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK) {
        return JNI_ERR;
    }

    jclass cls = env->FindClass("com/test/profiletest/NativeProtector");
    if (!cls) {
        LOGI("FindClass NativeProtector failed");
        return JNI_ERR;
    }

    jint n = (jint)(sizeof(g_methods) / sizeof(g_methods[0]));
    jint ret = env->RegisterNatives(cls, g_methods, n);
    env->DeleteLocalRef(cls);

    if (ret != JNI_OK) {
        LOGI("RegisterNatives failed: %d", ret);
        return JNI_ERR;
    }

    LOGI("JNI_OnLoad: %d methods registered via RegisterNatives", (int)n);
    return JNI_VERSION_1_6;
}
