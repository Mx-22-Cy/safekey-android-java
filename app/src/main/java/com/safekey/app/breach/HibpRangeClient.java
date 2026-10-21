package com.safekey.app.breach;

import android.os.Handler;
import android.os.Looper;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Network client for the HIBP Pwned Passwords
 * k-anonymity range API.
 *
 * This class accepts only a five-character SHA-1 prefix.
 * It never receives or transmits a raw password or
 * complete password hash.
 */
public final class HibpRangeClient
        implements HibpRangeSource {

    private static final String RANGE_ENDPOINT =
            "https://api.pwnedpasswords.com/range/";

    private static final String USER_AGENT =
            "SafeKey-Android/1.0";

    private static final int CONNECT_TIMEOUT_MS =
            10_000;

    private static final int READ_TIMEOUT_MS =
            10_000;

    /**
     * Maximum HIBP response size accepted by SafeKey.
     */
    static final int MAX_RESPONSE_LENGTH =
            1_048_576;

    private static final int READ_BUFFER_SIZE =
            4096;

    private final ExecutorService executorService;
    private final Handler mainHandler;

    public HibpRangeClient() {

        executorService =
                Executors.newSingleThreadExecutor();

        mainHandler =
                new Handler(
                        Looper.getMainLooper()
                );
    }

    @Override
    public void fetchRange(
            String hashPrefix,
            Callback callback
    ) {

        Objects.requireNonNull(
                callback,
                "callback"
        );

        final String normalizedPrefix =
                normalizePrefix(
                        hashPrefix
                );

        try {

            executorService.execute(() -> {

                try {

                    String responseBody =
                            executeRequest(
                                    normalizedPrefix
                            );

                    deliverSuccess(
                            callback,
                            responseBody
                    );

                } catch (Exception exception) {

                    deliverError(
                            callback,
                            exception
                    );
                }
            });

        } catch (RuntimeException schedulingError) {

            deliverError(
                    callback,
                    schedulingError
            );
        }
    }

    private String executeRequest(
            String normalizedPrefix
    ) throws IOException {

        URL url =
                new URL(
                        RANGE_ENDPOINT
                                + normalizedPrefix
                );

        HttpURLConnection connection =
                (HttpURLConnection)
                        url.openConnection();

        try {

            connection.setRequestMethod(
                    "GET"
            );

            connection.setConnectTimeout(
                    CONNECT_TIMEOUT_MS
            );

            connection.setReadTimeout(
                    READ_TIMEOUT_MS
            );

            connection.setInstanceFollowRedirects(
                    false
            );

            connection.setRequestProperty(
                    "User-Agent",
                    USER_AGENT
            );

            connection.setRequestProperty(
                    "Accept",
                    "text/plain"
            );

            connection.setRequestProperty(
                    "Add-Padding",
                    "true"
            );

            int responseCode =
                    connection.getResponseCode();

            if (responseCode
                    != HttpURLConnection.HTTP_OK) {

                throw new HibpHttpException(
                        responseCode
                );
            }

            try (
                    Reader reader =
                            new InputStreamReader(
                                    connection.getInputStream(),
                                    StandardCharsets.UTF_8
                            )
            ) {

                return readBoundedResponse(
                        reader
                );
            }

        } finally {

            connection.disconnect();
        }
    }

    /**
     * Reads the HTTP response in bounded chunks.
     *
     * No more than MAX_RESPONSE_LENGTH characters
     * are retained.
     */
    static String readBoundedResponse(
            Reader reader
    ) throws IOException {

        Objects.requireNonNull(
                reader,
                "reader"
        );

        StringBuilder response =
                new StringBuilder();

        char[] buffer =
                new char[READ_BUFFER_SIZE];

        while (true) {

            int remainingIncludingProbe =
                    MAX_RESPONSE_LENGTH
                            - response.length()
                            + 1;

            int charactersToRead =
                    Math.min(
                            buffer.length,
                            remainingIncludingProbe
                    );

            int charactersRead =
                    reader.read(
                            buffer,
                            0,
                            charactersToRead
                    );

            if (charactersRead == -1) {
                break;
            }

            if (response.length()
                    + charactersRead
                    > MAX_RESPONSE_LENGTH) {

                throw new IOException(
                        "HIBP response exceeded maximum allowed size."
                );
            }

            response.append(
                    buffer,
                    0,
                    charactersRead
            );
        }

        return response.toString();
    }

    /**
     * Validates the original prefix before normalizing case.
     *
     * Only exactly five ASCII hexadecimal characters
     * are accepted. Unicode case expansion must never
     * turn malformed input into a valid HIBP prefix.
     */
    static String normalizePrefix(
            String hashPrefix
    ) {

        if (hashPrefix == null) {

            throw new IllegalArgumentException(
                    "HIBP hash prefix must not be null."
            );
        }

        /*
         * IMPORTANT:
         * Validate the ORIGINAL string length before
         * any Unicode case conversion.
         */
        if (hashPrefix.length() != 5) {

            throw new IllegalArgumentException(
                    "HIBP hash prefix must contain exactly "
                            + "5 hexadecimal characters."
            );
        }

        /*
         * Validate every ORIGINAL character as ASCII hex.
         * Do not uppercase first because Unicode characters
         * may expand during case conversion.
         */
        for (int index = 0;
             index < hashPrefix.length();
             index++) {

            char character =
                    hashPrefix.charAt(index);

            if (!isAsciiHexDigit(
                    character
            )) {

                throw new IllegalArgumentException(
                        "HIBP hash prefix must contain only "
                                + "ASCII hexadecimal characters."
                );
            }
        }

        /*
         * Case normalization is safe only after the
         * original input has passed validation.
         */
        return hashPrefix.toUpperCase(
                Locale.US
        );
    }

    private static boolean isAsciiHexDigit(
            char character
    ) {

        return (character >= '0'
                && character <= '9')
                || (character >= 'A'
                && character <= 'F')
                || (character >= 'a'
                && character <= 'f');
    }

    private void deliverSuccess(
            Callback callback,
            String responseBody
    ) {

        mainHandler.post(
                () -> callback.onSuccess(
                        responseBody
                )
        );
    }

    private void deliverError(
            Callback callback,
            Exception exception
    ) {

        mainHandler.post(
                () -> callback.onError(
                        exception
                )
        );
    }

    public synchronized void shutdown() {

        if (executorService.isShutdown()) {
            return;
        }

        executorService.shutdownNow();
    }
}
