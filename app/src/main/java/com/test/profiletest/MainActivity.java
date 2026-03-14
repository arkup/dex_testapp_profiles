package com.test.profiletest;

import android.Manifest;
import android.app.Activity;
import android.content.ContentResolver;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.ContactsContract;
import android.telephony.SmsManager;
import android.telephony.TelephonyManager;
import android.app.ActivityManager;
import android.os.Debug;
import android.provider.Settings;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Test app for exercising all dexbgd breakpoint profiles and xref features.
 *
 * Each button triggers a specific API category:
 *   bp-crypto  → Cipher, SecretKeySpec, MessageDigest, Mac, KeyGenerator
 *   bp-network → URL.openConnection, HttpURLConnection, Socket
 *   bp-exec    → Runtime.exec, ProcessBuilder.start
 *   bp-loader  → DexClassLoader, Class.forName, Method.invoke
 *   bp-exfil   → TelephonyManager, ContentResolver.query
 *   bp-detect  → File.exists, PackageManager, Build, SystemProperties, Debug
 *   xref test  → hardcoded strings (URLs, passwords, API keys)
 *
 * Deploy:
 *   copy agent\build\libart_jit_tracer.so testapp-profiles\app\src\main\jniLibs\arm64-v8a\
 *   cd testapp-profiles && gradlew assembleDebug
 *   adb install -r app/build/outputs/apk/debug/app-debug.apk
 *   adb shell am start -n com.test.profiletest/.MainActivity
 *   adb shell cmd activity attach-agent com.test.profiletest libart_jit_tracer.so
 *   adb forward tcp:12345 localabstract:dexbgd
 */
public class MainActivity extends Activity {
    private static final String TAG = "ProfileTest";
    private TextView status;
    private TextView detectResult;
    private TextView jniResult;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        status = findViewById(R.id.status);
        detectResult = findViewById(R.id.detect_result);
        jniResult = findViewById(R.id.jni_result);

        findViewById(R.id.btn_crypto).setOnClickListener(v -> runOnThread(this::testCrypto));
        findViewById(R.id.btn_network).setOnClickListener(v -> runOnThread(this::testNetwork));
        findViewById(R.id.btn_exec).setOnClickListener(v -> runOnThread(this::testExec));
        findViewById(R.id.btn_loader).setOnClickListener(v -> runOnThread(this::testLoader));
        findViewById(R.id.btn_exfil).setOnClickListener(v -> runOnThread(this::testExfil));
        findViewById(R.id.btn_xref).setOnClickListener(v -> runOnThread(this::testXrefStrings));
        findViewById(R.id.btn_detect).setOnClickListener(v -> runOnThread(() -> {
            int result = testDetect();
            String label = result == 1 ? "Root: DETECTED (1)" : "Root: not detected (0)";
            runOnUiThread(() -> detectResult.setText(label));
        }));
        findViewById(R.id.btn_jni).setOnClickListener(v -> runOnThread(this::testNative));
        findViewById(R.id.btn_all).setOnClickListener(v -> runOnThread(this::testAll));

        setStatus("Ready. Attach agent, set breakpoints, then press buttons.");

        // Request dangerous permissions at runtime (required since API 23)
        requestPermissions(new String[]{
            Manifest.permission.READ_PHONE_STATE,
            Manifest.permission.READ_CONTACTS,
            Manifest.permission.SEND_SMS,
            Manifest.permission.ACCESS_FINE_LOCATION,
        }, 1);
    }

    private void runOnThread(Runnable r) {
        new Thread(() -> {
            try {
                r.run();
            } catch (Exception e) {
                Log.e(TAG, "Test failed", e);
                setStatus("ERROR: " + e.getMessage());
            }
        }).start();
    }

    private void setStatus(String msg) {
        runOnUiThread(() -> status.setText(msg));
        Log.i(TAG, msg);
    }

    // =====================================================================
    // bp-crypto: Cipher, SecretKeySpec, MessageDigest, Mac, KeyGenerator
    // =====================================================================

    private void testCrypto() {
        setStatus("Running crypto tests...");
        try {
            // SecretKeySpec (triggers bp-crypto)
            byte[] keyBytes = new byte[]{
                0x41, 0x45, 0x53, 0x2d, 0x4b, 0x45, 0x59, 0x2d,
                0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
            };
            SecretKeySpec aesKey = new SecretKeySpec(keyBytes,
                    "AES");

            // IvParameterSpec
            byte[] ivBytes = new byte[]{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Cipher.getInstance + Cipher.init + Cipher.doFinal (encrypt)
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, iv);
            byte[] plaintext = "Sensitive data: password=hunter2".getBytes();
            byte[] encrypted = cipher.doFinal(plaintext);
            Log.i(TAG, "AES encrypted: " + encrypted.length + " bytes");

            // Cipher.doFinal (decrypt)
            Cipher decipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
            byte[] decrypted = decipher.doFinal(encrypted);
            Log.i(TAG, "AES decrypted: " + new String(decrypted));

            // MessageDigest.update + MessageDigest.digest
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(plaintext);
            byte[] hash = md.digest();
            Log.i(TAG, "SHA-256 hash: " + hash.length + " bytes");

            // Mac.init + Mac.doFinal
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(aesKey);
            byte[] hmac = mac.doFinal(plaintext);
            Log.i(TAG, "HMAC-SHA256: " + hmac.length + " bytes");

            // KeyGenerator.generateKey
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(256);
            SecretKey generated = keygen.generateKey();
            Log.i(TAG, "Generated AES key: " + generated.getEncoded().length + " bytes");

            setStatus("Crypto tests PASSED");
        } catch (Exception e) {
            setStatus("Crypto FAILED: " + e.getMessage());
            Log.e(TAG, "crypto", e);
        }
    }

    // =====================================================================
    // bp-network: URL.openConnection, HttpURLConnection, Socket
    // =====================================================================

    private void testNetwork() {
        setStatus("Running network tests...");
        try {
            // URL.openConnection + HttpURLConnection.connect
            String targetUrl = "http://httpbin.org/get";
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            try {
                conn.connect();
                int code = conn.getResponseCode();
                Log.i(TAG, "HTTP GET " + targetUrl + " → " + code);

                // HttpURLConnection.getInputStream
                if (code == 200) {
                    InputStream in = conn.getInputStream();
                    BufferedReader reader = new BufferedReader(new InputStreamReader(in));
                    String line = reader.readLine();
                    Log.i(TAG, "Response first line: " + (line != null ? line.substring(0, Math.min(80, line.length())) : "null"));
                    reader.close();
                }
            } finally {
                conn.disconnect();
            }

            // Socket — try connecting to localhost (will fail, that's fine)
            try {
                Socket sock = new Socket();
                sock.connect(new java.net.InetSocketAddress("127.0.0.1", 9999), 1000);
                sock.close();
            } catch (Exception e) {
                Log.i(TAG, "Socket connect (expected fail): " + e.getMessage());
            }

            setStatus("Network tests PASSED");
        } catch (Exception e) {
            setStatus("Network FAILED: " + e.getMessage());
            Log.e(TAG, "network", e);
        }
    }

    // =====================================================================
    // bp-exec: Runtime.exec, ProcessBuilder.start
    // =====================================================================

    private void testExec() {
        setStatus("Running exec tests...");
        try {
            // Runtime.exec
            Process p1 = Runtime.getRuntime().exec("id");
            BufferedReader r1 = new BufferedReader(new InputStreamReader(p1.getInputStream()));
            String id = r1.readLine();
            r1.close();
            p1.waitFor();
            Log.i(TAG, "Runtime.exec('id') → " + id);

            // ProcessBuilder.start
            ProcessBuilder pb = new ProcessBuilder("ls", "/system/bin/sh");
            pb.redirectErrorStream(true);
            Process p2 = pb.start();
            BufferedReader r2 = new BufferedReader(new InputStreamReader(p2.getInputStream()));
            String ls = r2.readLine();
            r2.close();
            p2.waitFor();
            Log.i(TAG, "ProcessBuilder('ls') → " + ls);

            setStatus("Exec tests PASSED");
        } catch (Exception e) {
            setStatus("Exec FAILED: " + e.getMessage());
            Log.e(TAG, "exec", e);
        }
    }

    // =====================================================================
    // bp-loader: DexClassLoader, InMemoryDexClassLoader, reflection
    // =====================================================================

    // Minimal DEX containing com.test.payload.DynamicPayload with:
    //   public static String getMessage() → "Hello from dynamic DEX!"
    // Built with: javac --release 8 | d8 --min-api 26
    private static final byte[] DEX_BYTES = {
        (byte)0x64, (byte)0x65, (byte)0x78, (byte)0x0A, (byte)0x30, (byte)0x33, (byte)0x38, (byte)0x00, (byte)0x5C, (byte)0x83, (byte)0x4B, (byte)0x11, (byte)0xEE, (byte)0xD2, (byte)0x13, (byte)0xB3,
        (byte)0x55, (byte)0x5A, (byte)0xEE, (byte)0xF5, (byte)0x42, (byte)0x24, (byte)0x31, (byte)0x13, (byte)0x8F, (byte)0x83, (byte)0x41, (byte)0x95, (byte)0xC7, (byte)0x53, (byte)0x67, (byte)0xC5,
        (byte)0xFC, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x70, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x78, (byte)0x56, (byte)0x34, (byte)0x12, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x74, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x0A, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x70, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x98, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xA8, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xC0, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xD8, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0xF8, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x34, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x3C, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x51, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x6A, (byte)0x01, (byte)0x00, (byte)0x00,
        (byte)0x6D, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x90, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xA4, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xB8, (byte)0x01, (byte)0x00, (byte)0x00,
        (byte)0xBB, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0xC7, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x06, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x07, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x07, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x08, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x01, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x66, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x28, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x1A, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x11, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x01, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x2C, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x70, (byte)0x10, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0E, (byte)0x00, (byte)0x08, (byte)0x00, (byte)0x0E, (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x0E, (byte)0x3C,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x3C, (byte)0x69, (byte)0x6E, (byte)0x69, (byte)0x74, (byte)0x3E, (byte)0x00, (byte)0x13, (byte)0x44, (byte)0x79, (byte)0x6E,
        (byte)0x61, (byte)0x6D, (byte)0x69, (byte)0x63, (byte)0x50, (byte)0x61, (byte)0x79, (byte)0x6C, (byte)0x6F, (byte)0x61, (byte)0x64, (byte)0x2E, (byte)0x6A, (byte)0x61, (byte)0x76, (byte)0x61,
        (byte)0x00, (byte)0x17, (byte)0x48, (byte)0x65, (byte)0x6C, (byte)0x6C, (byte)0x6F, (byte)0x20, (byte)0x66, (byte)0x72, (byte)0x6F, (byte)0x6D, (byte)0x20, (byte)0x64, (byte)0x79, (byte)0x6E,
        (byte)0x61, (byte)0x6D, (byte)0x69, (byte)0x63, (byte)0x20, (byte)0x44, (byte)0x45, (byte)0x58, (byte)0x21, (byte)0x00, (byte)0x01, (byte)0x4C, (byte)0x00, (byte)0x21, (byte)0x4C, (byte)0x63,
        (byte)0x6F, (byte)0x6D, (byte)0x2F, (byte)0x74, (byte)0x65, (byte)0x73, (byte)0x74, (byte)0x2F, (byte)0x70, (byte)0x61, (byte)0x79, (byte)0x6C, (byte)0x6F, (byte)0x61, (byte)0x64, (byte)0x2F,
        (byte)0x44, (byte)0x79, (byte)0x6E, (byte)0x61, (byte)0x6D, (byte)0x69, (byte)0x63, (byte)0x50, (byte)0x61, (byte)0x79, (byte)0x6C, (byte)0x6F, (byte)0x61, (byte)0x64, (byte)0x3B, (byte)0x00,
        (byte)0x12, (byte)0x4C, (byte)0x6A, (byte)0x61, (byte)0x76, (byte)0x61, (byte)0x2F, (byte)0x6C, (byte)0x61, (byte)0x6E, (byte)0x67, (byte)0x2F, (byte)0x4F, (byte)0x62, (byte)0x6A, (byte)0x65,
        (byte)0x63, (byte)0x74, (byte)0x3B, (byte)0x00, (byte)0x12, (byte)0x4C, (byte)0x6A, (byte)0x61, (byte)0x76, (byte)0x61, (byte)0x2F, (byte)0x6C, (byte)0x61, (byte)0x6E, (byte)0x67, (byte)0x2F,
        (byte)0x53, (byte)0x74, (byte)0x72, (byte)0x69, (byte)0x6E, (byte)0x67, (byte)0x3B, (byte)0x00, (byte)0x01, (byte)0x56, (byte)0x00, (byte)0x0A, (byte)0x67, (byte)0x65, (byte)0x74, (byte)0x4D,
        (byte)0x65, (byte)0x73, (byte)0x73, (byte)0x61, (byte)0x67, (byte)0x65, (byte)0x00, (byte)0x9C, (byte)0x01, (byte)0x7E, (byte)0x7E, (byte)0x44, (byte)0x38, (byte)0x7B, (byte)0x22, (byte)0x62,
        (byte)0x61, (byte)0x63, (byte)0x6B, (byte)0x65, (byte)0x6E, (byte)0x64, (byte)0x22, (byte)0x3A, (byte)0x22, (byte)0x64, (byte)0x65, (byte)0x78, (byte)0x22, (byte)0x2C, (byte)0x22, (byte)0x63,
        (byte)0x6F, (byte)0x6D, (byte)0x70, (byte)0x69, (byte)0x6C, (byte)0x61, (byte)0x74, (byte)0x69, (byte)0x6F, (byte)0x6E, (byte)0x2D, (byte)0x6D, (byte)0x6F, (byte)0x64, (byte)0x65, (byte)0x22,
        (byte)0x3A, (byte)0x22, (byte)0x64, (byte)0x65, (byte)0x62, (byte)0x75, (byte)0x67, (byte)0x22, (byte)0x2C, (byte)0x22, (byte)0x68, (byte)0x61, (byte)0x73, (byte)0x2D, (byte)0x63, (byte)0x68,
        (byte)0x65, (byte)0x63, (byte)0x6B, (byte)0x73, (byte)0x75, (byte)0x6D, (byte)0x73, (byte)0x22, (byte)0x3A, (byte)0x66, (byte)0x61, (byte)0x6C, (byte)0x73, (byte)0x65, (byte)0x2C, (byte)0x22,
        (byte)0x6D, (byte)0x69, (byte)0x6E, (byte)0x2D, (byte)0x61, (byte)0x70, (byte)0x69, (byte)0x22, (byte)0x3A, (byte)0x32, (byte)0x36, (byte)0x2C, (byte)0x22, (byte)0x73, (byte)0x68, (byte)0x61,
        (byte)0x2D, (byte)0x31, (byte)0x22, (byte)0x3A, (byte)0x22, (byte)0x66, (byte)0x61, (byte)0x63, (byte)0x65, (byte)0x64, (byte)0x66, (byte)0x34, (byte)0x31, (byte)0x62, (byte)0x62, (byte)0x64,
        (byte)0x32, (byte)0x38, (byte)0x62, (byte)0x35, (byte)0x36, (byte)0x33, (byte)0x64, (byte)0x31, (byte)0x65, (byte)0x39, (byte)0x65, (byte)0x30, (byte)0x39, (byte)0x63, (byte)0x35, (byte)0x66,
        (byte)0x37, (byte)0x32, (byte)0x64, (byte)0x37, (byte)0x63, (byte)0x35, (byte)0x63, (byte)0x61, (byte)0x35, (byte)0x39, (byte)0x38, (byte)0x64, (byte)0x35, (byte)0x22, (byte)0x2C, (byte)0x22,
        (byte)0x76, (byte)0x65, (byte)0x72, (byte)0x73, (byte)0x69, (byte)0x6F, (byte)0x6E, (byte)0x22, (byte)0x3A, (byte)0x22, (byte)0x38, (byte)0x2E, (byte)0x32, (byte)0x2E, (byte)0x32, (byte)0x2D,
        (byte)0x64, (byte)0x65, (byte)0x76, (byte)0x22, (byte)0x7D, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x81, (byte)0x80, (byte)0x04, (byte)0x90, (byte)0x02,
        (byte)0x01, (byte)0x09, (byte)0xF8, (byte)0x01, (byte)0x0B, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x0A, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x70, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x04, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x98, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xA8, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0xC0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xD8, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x01, (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xF8, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x03, (byte)0x20, (byte)0x00, (byte)0x00,
        (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x28, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x02, (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x0A, (byte)0x00, (byte)0x00, (byte)0x00,
        (byte)0x34, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x20, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x66, (byte)0x02, (byte)0x00, (byte)0x00,
        (byte)0x00, (byte)0x10, (byte)0x00, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x74, (byte)0x02, (byte)0x00, (byte)0x00,
    };

    private void testLoader() {
        setStatus("Running loader/reflection tests...");
        try {
            // --- Reflection: Class.forName + Method.invoke ---
            Class<?> cls = Class.forName("java.lang.StringBuilder");
            Log.i(TAG, "Class.forName → " + cls.getName());

            Object sb = cls.getDeclaredConstructor().newInstance();
            Method appendMethod = cls.getMethod("append", String.class);
            appendMethod.invoke(sb, "reflected_data");
            Method toStringMethod = cls.getMethod("toString");
            String result = (String) toStringMethod.invoke(sb);
            Log.i(TAG, "Method.invoke → " + result);

            // --- DexClassLoader: write DEX to file, load from file path ---
            // This is the #1 technique malware uses to load hidden payloads
            try {
                File dexFile = new File(getFilesDir(), "payload.dex");
                if (dexFile.exists()) { dexFile.setWritable(true); dexFile.delete(); }
                FileOutputStream fos = new FileOutputStream(dexFile);
                fos.write(DEX_BYTES);
                fos.close();
                dexFile.setReadOnly();  // Android 14+ rejects writable DEX files
                Log.i(TAG, "Wrote payload DEX: " + dexFile.getAbsolutePath() + " (" + DEX_BYTES.length + " bytes)");

                dalvik.system.DexClassLoader dcl = new dalvik.system.DexClassLoader(
                    dexFile.getAbsolutePath(),
                    getCacheDir().getAbsolutePath(),
                    null,
                    getClassLoader()
                );
                Class<?> payloadCls = dcl.loadClass("com.test.payload.DynamicPayload");
                Method getMsg = payloadCls.getMethod("getMessage");
                String msg = (String) getMsg.invoke(null);
                Log.i(TAG, "DexClassLoader → " + payloadCls.getName() + ".getMessage() = " + msg);
            } catch (Exception e) {
                Log.w(TAG, "DexClassLoader test: " + e.getMessage());
            }

            // --- InMemoryDexClassLoader: load DEX from ByteBuffer ---
            // This is the #2 technique — loads DEX directly from memory (no file on disk)
            try {
                ByteBuffer dexBuffer = ByteBuffer.wrap(DEX_BYTES);
                dalvik.system.InMemoryDexClassLoader imdcl =
                    new dalvik.system.InMemoryDexClassLoader(dexBuffer, getClassLoader());
                Class<?> memCls = imdcl.loadClass("com.test.payload.DynamicPayload");
                Method getMsg = memCls.getMethod("getMessage");
                String msg = (String) getMsg.invoke(null);
                Log.i(TAG, "InMemoryDexClassLoader → " + memCls.getName() + ".getMessage() = " + msg);
            } catch (Exception e) {
                Log.w(TAG, "InMemoryDexClassLoader test: " + e.getMessage());
            }

            setStatus("Loader tests PASSED");
        } catch (Exception e) {
            setStatus("Loader FAILED: " + e.getMessage());
            Log.e(TAG, "loader", e);
        }
    }

    // =====================================================================
    // bp-exfil: TelephonyManager, ContentResolver, SmsManager
    // =====================================================================

    private void testExfil() {
        setStatus("Running exfil tests...");
        try {
            // TelephonyManager.getDeviceId (needs READ_PHONE_STATE)
            try {
                TelephonyManager tm = (TelephonyManager) getSystemService(TELEPHONY_SERVICE);
                String imei = tm.getDeviceId();
                Log.i(TAG, "TelephonyManager.getDeviceId → " + imei);
            } catch (SecurityException e) {
                Log.i(TAG, "getDeviceId (no permission): " + e.getMessage());
            }

            // ContentResolver.query — query contacts
            try {
                ContentResolver cr = getContentResolver();
                Cursor cursor = cr.query(
                    ContactsContract.Contacts.CONTENT_URI,
                    new String[]{ ContactsContract.Contacts.DISPLAY_NAME },
                    null, null, null
                );
                int count = cursor != null ? cursor.getCount() : 0;
                if (cursor != null) cursor.close();
                Log.i(TAG, "ContentResolver.query contacts → " + count + " rows");
            } catch (SecurityException e) {
                Log.i(TAG, "query contacts (no permission): " + e.getMessage());
            }

            // SmsManager — get default instance (don't actually send)
            try {
                SmsManager sms = SmsManager.getDefault();
                Log.i(TAG, "SmsManager.getDefault() → " + sms);
                // NOT actually sending — just triggering the API reference
            } catch (Exception e) {
                Log.i(TAG, "SmsManager: " + e.getMessage());
            }

            setStatus("Exfil tests PASSED");
        } catch (Exception e) {
            setStatus("Exfil FAILED: " + e.getMessage());
            Log.e(TAG, "exfil", e);
        }
    }

    // =====================================================================
    // xref test: hardcoded strings for testing xref / xref-bp commands
    // =====================================================================

    // These strings are embedded in the DEX constant pool.
    // Use: apk com.test.profiletest → xref c2-server → see this method
    private static final String C2_SERVER = "http://malware-c2.evil.com/beacon";
    private static final String EXFIL_ENDPOINT = "https://exfil.darkweb.onion/upload";
    private static final String API_KEY = "sk-FAKE-api-key-1234567890abcdef";
    private static final String HARDCODED_PASSWORD = "admin_password_2024";
    private static final String AES_KEY_STRING = "SuperSecretAES128Key!!";
    private static final String SQLITE_DB = "/data/data/com.target.app/databases/credentials.db";

    private void testXrefStrings() {
        setStatus("Running xref string tests...");

        // These method calls force the const-string instructions into bytecodes
        String beacon = buildBeaconUrl(42);
        Log.i(TAG, "Beacon URL: " + beacon);

        String payload = buildExfilPayload("device_id_123");
        Log.i(TAG, "Exfil payload: " + payload);

        String auth = getAuthHeader();
        Log.i(TAG, "Auth header: " + auth);

        boolean valid = checkPassword("user_input");
        Log.i(TAG, "Password check: " + valid);

        byte[] key = deriveKeyFromString();
        Log.i(TAG, "Derived key: " + key.length + " bytes");

        String dbPath = getTargetDatabase();
        Log.i(TAG, "DB path: " + dbPath);

        setStatus("Xref tests PASSED");
    }

    private String buildBeaconUrl(int botId) {
        // xref "malware-c2" or "beacon" will find this method
        return C2_SERVER + "?id=" + botId + "&key=" + API_KEY;
    }

    private String buildExfilPayload(String deviceId) {
        // xref "exfil" or "darkweb" will find this method
        return "{\"url\":\"" + EXFIL_ENDPOINT + "\",\"device\":\"" + deviceId + "\"}";
    }

    private String getAuthHeader() {
        // xref "api-key" or "sk-FAKE" will find this method
        return "Authorization: Bearer " + API_KEY;
    }

    private boolean checkPassword(String input) {
        // xref "admin_password" will find this method
        return HARDCODED_PASSWORD.equals(input);
    }

    private byte[] deriveKeyFromString() {
        // xref "SuperSecret" will find this method
        try {
            return AES_KEY_STRING.getBytes("UTF-8");
        } catch (Exception e) {
            return new byte[0];
        }
    }

    private String getTargetDatabase() {
        // xref "credentials.db" will find this method
        return SQLITE_DB;
    }

    // =====================================================================
    // bp-detect: root/tamper detection APIs
    // =====================================================================

    private int testDetect() {
        setStatus("Running detect (root/tamper) tests...");
        try {
            int rooted = 0;

            // File.exists — check common root binary paths
            String[] suPaths = {
                "/system/xbin/su", "/system/bin/su", "/sbin/su",
                "/system/app/Superuser.apk", "/data/local/xbin/su"
            };
            for (String path : suPaths) {
                boolean exists = new File(path).exists();
                Log.i(TAG, "File.exists(\"" + path + "\") → " + exists);
                if (exists) rooted = 1;
            }

            // PackageManager.getPackageInfo — check for root/hook packages
            PackageManager pm = getPackageManager();
            String[] rootPkgs = {
                "com.topjohnwu.magisk", "eu.chainfire.supersu",
                "de.robv.android.xposed.installer", "com.saurik.substrate"
            };
            for (String pkg : rootPkgs) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    Log.i(TAG, "PackageManager.getPackageInfo(\"" + pkg + "\") → FOUND");
                    rooted = 1;
                } catch (PackageManager.NameNotFoundException e) {
                    Log.i(TAG, "PackageManager.getPackageInfo(\"" + pkg + "\") → not found");
                }
            }

            // PackageManager.getInstallerPackageName
            try {
                String installer = pm.getInstallerPackageName(getPackageName());
                Log.i(TAG, "getInstallerPackageName → " + installer);
            } catch (Exception e) {
                Log.i(TAG, "getInstallerPackageName: " + e.getMessage());
            }

            // Build fields — Build.<clinit> triggers on first access
            String tags = android.os.Build.TAGS;
            String fingerprint = android.os.Build.FINGERPRINT;
            String product = android.os.Build.PRODUCT;
            Log.i(TAG, "Build.TAGS → " + tags);
            Log.i(TAG, "Build.FINGERPRINT → " + fingerprint);
            Log.i(TAG, "Build.PRODUCT → " + product);
            if (tags != null && tags.contains("test-keys")) rooted = 1;

            // SystemProperties.get via reflection (hidden API)
            try {
                Class<?> sysPropClass = Class.forName("android.os.SystemProperties");
                Method getMethod = sysPropClass.getMethod("get", String.class);
                String roDebug = (String) getMethod.invoke(null, "ro.debuggable");
                String roSecure = (String) getMethod.invoke(null, "ro.secure");
                String roBuild = (String) getMethod.invoke(null, "ro.build.type");
                Log.i(TAG, "SystemProperties.get(ro.debuggable) → " + roDebug);
                Log.i(TAG, "SystemProperties.get(ro.secure) → " + roSecure);
                Log.i(TAG, "SystemProperties.get(ro.build.type) → " + roBuild);
                if ("1".equals(roDebug) || "0".equals(roSecure)
                        || "eng".equals(roBuild) || "userdebug".equals(roBuild)) rooted = 1;
            } catch (Exception e) {
                Log.w(TAG, "SystemProperties reflection: " + e.getMessage());
            }

            // ActivityManager.getRunningAppProcesses
            try {
                ActivityManager am = (ActivityManager) getSystemService(ACTIVITY_SERVICE);
                java.util.List<ActivityManager.RunningAppProcessInfo> procs = am.getRunningAppProcesses();
                Log.i(TAG, "getRunningAppProcesses → " + (procs != null ? procs.size() : 0) + " processes");
            } catch (Exception e) {
                Log.w(TAG, "getRunningAppProcesses: " + e.getMessage());
            }

            // Debug.isDebuggerConnected
            boolean debuggerAttached = Debug.isDebuggerConnected();
            Log.i(TAG, "Debug.isDebuggerConnected → " + debuggerAttached);

            // Settings.Secure.getString — get Android ID
            try {
                String androidId = Settings.Secure.getString(
                    getContentResolver(), Settings.Secure.ANDROID_ID);
                Log.i(TAG, "Settings.Secure.getString(ANDROID_ID) → " + androidId);
            } catch (Exception e) {
                Log.w(TAG, "Settings.Secure: " + e.getMessage());
            }

            Log.i(TAG, "root=" + rooted);
            setStatus("Detect tests PASSED — root=" + rooted);
            return rooted;
        } catch (Exception e) {
            setStatus("Detect FAILED: " + e.getMessage());
            Log.e(TAG, "detect", e);
            return 0;
        }
    }

    // =====================================================================
    // jni monitor: NativeProtector via RegisterNatives
    // =====================================================================

    /**
     * Calls all four native methods and displays their results.
     *
     * The library uses RegisterNatives (not Java_... symbols) so the bindings
     * are invisible to static analysis — exactly what jni monitor captures.
     *
     * Workflow:
     *   1. jni monitor              (start capturing RegisterNatives)
     *   2. Press this button        (library loads, JNI_OnLoad fires, bindings captured)
     *   3. Key 5 -> JNI tab         (see libnative_protector.so+0xXXXX for each method)
     *   4. jni redirect libnative_protector.so+0xXXXX block  (or use class sig)
     *   5. Press button again       (see return values change in the result display)
     */
    private void testNative() {
        setStatus("Running JNI native protector test...");
        try {
            NativeProtector guard = new NativeProtector();

            boolean protected_  = guard.isProtected();
            int     integrity   = guard.checkIntegrity();
            String  licenseKey  = guard.getLicenseKey();
            boolean debugger    = guard.isDebuggerPresent();

            String result = "isProtected=" + protected_
                + "  checkIntegrity=" + integrity
                + "\nlicenseKey=" + licenseKey
                + "\nisDebugger=" + debugger;

            Log.i(TAG, "NativeProtector: " + result);
            runOnUiThread(() -> jniResult.setText(result));
            setStatus("JNI test done — redirect methods and press again to see change");
        } catch (Exception e) {
            setStatus("JNI FAILED: " + e.getMessage());
            Log.e(TAG, "native", e);
        }
    }

    // =====================================================================
    // Run all tests
    // =====================================================================

    private void testAll() {
        setStatus("Running ALL tests...");
        testCrypto();
        testNetwork();
        testExec();
        testLoader();
        testExfil();
        int rootResult = testDetect();
        String label = rootResult == 1 ? "Root: DETECTED (1)" : "Root: not detected (0)";
        runOnUiThread(() -> detectResult.setText(label));
        testXrefStrings();
        testNative();
        setStatus("ALL tests completed");
    }
}
