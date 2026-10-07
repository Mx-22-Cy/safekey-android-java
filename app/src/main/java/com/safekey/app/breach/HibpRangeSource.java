package com.safekey.app.breach;

/**
 * Boundary for retrieving a HIBP Pwned Passwords hash range.
 *
 * Implementations receive only the first five hexadecimal characters
 * of a password SHA-1 hash. Raw passwords and complete hashes must
 * never be passed through this interface.
 */
public interface HibpRangeSource {

    void fetchRange(
            String hashPrefix,
            Callback callback
    );

    interface Callback {

        void onSuccess(
                String responseBody
        );

        void onError(
                Exception exception
        );
    }
}
