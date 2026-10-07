package com.safekey.app.breach;

import android.os.Handler;
import android.os.Looper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
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

            /*
             * HIBP response padding reduces information
             * leakage based on response size.
             *
             * Padding rows have count 0 and are removed
             * later by HibpRangeParser.
             */
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
                    BufferedReader reader =
                            new BufferedReader(
                                    new InputStreamReader(
                                            connection.getInputStream(),
                                            StandardCharsets.UTF_8
                                    )
                            )
            ) {

                StringBuilder response =
                        new StringBuilder();

                String line;

                while ((line =
                        reader.readLine()) != null) {

                    response.append(line)
                            .append('\n');
                }

                return response.toString();
            }

        } finally {

            connection.disconnect();
        }
    }

    static String normalizePrefix(
            String hashPrefix
    ) {

        if (hashPrefix == null) {

            throw new IllegalArgumentException(
                    "HIBP hash prefix must not be null."
            );
        }

        String normalized =
                hashPrefix.toUpperCase(
                        Locale.US
                );

        if (normalized.length() != 5) {

            throw new IllegalArgumentException(
                    "HIBP hash prefix must contain exactly "
                            + "5 hexadecimal characters."
            );
        }

        for (int index = 0;
             index < normalized.length();
             index++) {

            char character =
                    normalized.charAt(index);

            boolean hexadecimal =
                    (character >= '0'
                            && character <= '9')
                            || (character >= 'A'
                            && character <= 'F');

            if (!hexadecimal) {

                throw new IllegalArgumentException(
                        "HIBP hash prefix must contain only "
                                + "hexadecimal characters."
                );
            }
        }

        return normalized;
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