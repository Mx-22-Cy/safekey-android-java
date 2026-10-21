package com.safekey.app.breach;

import java.util.Objects;

/**
 * Test-only fake implementation of HibpRangeSource.
 *
 * It allows unit tests to simulate a successful HIBP
 * response or an API/network error without using the
 * real internet service.
 */
final class FakeHibpRangeSource
        implements HibpRangeSource {

    private final String responseBody;
    private final Exception error;

    private String lastHashPrefix;
    private int requestCount;

    private FakeHibpRangeSource(
            String responseBody,
            Exception error
    ) {
        this.responseBody = responseBody;
        this.error = error;
    }

    static FakeHibpRangeSource success(
            String responseBody
    ) {
        return new FakeHibpRangeSource(
                responseBody,
                null
        );
    }

    static FakeHibpRangeSource failure(
            Exception error
    ) {
        return new FakeHibpRangeSource(
                null,
                Objects.requireNonNull(
                        error,
                        "error"
                )
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

        lastHashPrefix = hashPrefix;
        requestCount++;

        if (error != null) {

            callback.onError(
                    error
            );

            return;
        }

        callback.onSuccess(
                responseBody
        );
    }

    String getLastHashPrefix() {
        return lastHashPrefix;
    }

    int getRequestCount() {
        return requestCount;
    }
}
