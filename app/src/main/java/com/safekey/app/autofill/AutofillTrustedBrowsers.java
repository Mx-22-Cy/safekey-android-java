package com.safekey.app.autofill;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;

import java.security.MessageDigest;

/**
 * Allowlist of browser package names and verified signing identities.
 *
 * Browser trust does not replace HTTPS origin validation,
 * exact website matching, or SafeKey authentication.
 */
public final class AutofillTrustedBrowsers {

    private static final String CHROME_PACKAGE =
            "com.android.chrome";

    private static final String SAMSUNG_PACKAGE =
            "com.sec.android.app.sbrowser";

    private static final byte[] CHROME_SHA256 = decodeHex(
            "f0fd6c5b410f25cb25c3b53346c8972f"
          + "ae30f8ee7411df910480ad6b2d60db83"
    );

    private static final byte[] SAMSUNG_SHA256 = decodeHex(
            "34df0e7a9f1cf1892e45c056b4973cd8"
          + "1ccf148a4050d11aea4ac5a65f900a42"
    );

    private AutofillTrustedBrowsers() {
    }

    public static boolean isTrustedBrowser(
            Context context,
            String packageName
    ) {
        if (context == null || packageName == null) {
            return false;
        }

        byte[] expected = expectedCertificate(packageName);

        if (expected == null) {
            return false;
        }

        try {
            PackageManager manager = context.getPackageManager();
            Signature[] signatures;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                PackageInfo info = manager.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNING_CERTIFICATES
                );

                if (info.signingInfo == null) {
                    return false;
                }

                signatures = info.signingInfo.getApkContentsSigners();
            } else {
                @SuppressWarnings("deprecation")
                PackageInfo info = manager.getPackageInfo(
                        packageName,
                        PackageManager.GET_SIGNATURES
                );

                signatures = info.signatures;
            }

            if (signatures == null
                    || signatures.length != 1
                    || signatures[0] == null) {
                return false;
            }

            byte[] actual = MessageDigest.getInstance("SHA-256")
                    .digest(signatures[0].toByteArray());

            return MessageDigest.isEqual(actual, expected);

        } catch (Exception exception) {
            return false;
        }
    }

    private static byte[] expectedCertificate(String packageName) {
        switch (packageName) {
            case CHROME_PACKAGE:
                return CHROME_SHA256;
            case SAMSUNG_PACKAGE:
                return SAMSUNG_SHA256;
            default:
                return null;
        }
    }

    private static byte[] decodeHex(String value) {
        if (value == null || value.length() != 64) {
            throw new IllegalArgumentException(
                    "Invalid certificate fingerprint"
            );
        }

        byte[] bytes = new byte[value.length() / 2];

        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);

            if (high < 0 || low < 0) {
                throw new IllegalArgumentException(
                        "Invalid certificate fingerprint"
                );
            }

            bytes[i] = (byte) ((high << 4) | low);
        }

        return bytes;
    }
}