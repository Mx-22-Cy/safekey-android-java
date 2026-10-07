package com.safekey.app.breach;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.Objects;

/**
 * Converts the raw HIBP range API response into validated
 * breach-range entries and safe, typed errors.
 *
 * This service does not receive a password or complete hash.
 * The caller supplies only the five-character SHA-1 prefix.
 */
public final class HibpRangeService {

    private final HibpRangeSource rangeSource;

    public HibpRangeService(
            HibpRangeSource rangeSource
    ) {
        this.rangeSource =
                Objects.requireNonNull(
                        rangeSource,
                        "rangeSource"
                );
    }

    public void fetchEntries(
            String hashPrefix,
            Callback callback
    ) {
        Objects.requireNonNull(
                callback,
                "callback"
        );

        try {

            rangeSource.fetchRange(
                    hashPrefix,
                    new HibpRangeSource.Callback() {

                        @Override
                        public void onSuccess(
                                String responseBody
                        ) {
                            try {

                                List<HibpRangeEntry> entries =
                                        HibpRangeParser.parse(
                                                responseBody
                                        );

                                callback.onSuccess(
                                        entries
                                );

                            } catch (IllegalArgumentException exception) {

                                callback.onError(
                                        HibpRangeError
                                                .invalidResponse()
                                );
                            }
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {
                            callback.onError(
                                    mapError(
                                            exception
                                    )
                            );
                        }
                    }
            );

        } catch (IllegalArgumentException exception) {

            callback.onError(
                    HibpRangeError.invalidRequest()
            );

        } catch (RuntimeException exception) {

            callback.onError(
                    HibpRangeError.unknown()
            );
        }
    }

    private static HibpRangeError mapError(
            Exception exception
    ) {
        if (exception == null) {
            return HibpRangeError.unknown();
        }

        if (exception
                instanceof SocketTimeoutException) {

            return HibpRangeError.timeout();
        }

        if (exception
                instanceof HibpHttpException) {

            HibpHttpException httpException =
                    (HibpHttpException) exception;

            return HibpRangeError.httpError(
                    httpException.getStatusCode()
            );
        }

        if (exception
                instanceof IOException) {

            return HibpRangeError.networkError();
        }

        if (exception
                instanceof IllegalArgumentException) {

            return HibpRangeError.invalidRequest();
        }

        return HibpRangeError.unknown();
    }

    public interface Callback {

        void onSuccess(
                List<HibpRangeEntry> entries
        );

        void onError(
                HibpRangeError error
        );
    }
}
