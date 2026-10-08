package com.safekey.app.breach;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

public class HibpRangeServiceTest {

    @Test
    public void fetchEntries_success_parsesEntriesAndPassesPrefix() {

        String suffix =
                repeat('A', 35);

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        suffix + ":25\n"
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<List<HibpRangeEntry>> result =
                new AtomicReference<>();

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new HibpRangeService.Callback() {

                    @Override
                    public void onSuccess(
                            List<HibpRangeEntry> entries
                    ) {
                        result.set(
                                entries
                        );
                    }

                    @Override
                    public void onError(
                            HibpRangeError serviceError
                    ) {
                        error.set(
                                serviceError
                        );
                    }
                }
        );

        assertNull(
                error.get()
        );

        assertNotNull(
                result.get()
        );

        assertEquals(
                1,
                result.get().size()
        );

        assertEquals(
                suffix,
                result.get()
                        .get(0)
                        .getHashSuffix()
        );

        assertEquals(
                25L,
                result.get()
                        .get(0)
                        .getCount()
        );

        assertEquals(
                "ABCDE",
                source.getLastHashPrefix()
        );

        assertEquals(
                1,
                source.getRequestCount()
        );
    }

    @Test
    public void fetchEntries_paddingEntries_areRemoved() {

        String realSuffix =
                repeat('A', 35);

        String paddingSuffix =
                repeat('B', 35);

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        realSuffix
                                + ":9\n"
                                + paddingSuffix
                                + ":0\n"
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<List<HibpRangeEntry>> result =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new HibpRangeService.Callback() {

                    @Override
                    public void onSuccess(
                            List<HibpRangeEntry> entries
                    ) {
                        result.set(
                                entries
                        );
                    }

                    @Override
                    public void onError(
                            HibpRangeError error
                    ) {
                        // Not expected.
                    }
                }
        );

        assertNotNull(
                result.get()
        );

        assertEquals(
                1,
                result.get().size()
        );

        assertEquals(
                9L,
                result.get()
                        .get(0)
                        .getCount()
        );
    }

    @Test
    public void fetchEntries_onlyPaddingEntries_returnsSuccessfulEmptyList() {

        String paddingSuffix =
                repeat('B', 35);

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        paddingSuffix + ":0\n"
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<List<HibpRangeEntry>> result =
                new AtomicReference<>();

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new HibpRangeService.Callback() {

                    @Override
                    public void onSuccess(
                            List<HibpRangeEntry> entries
                    ) {
                        result.set(
                                entries
                        );
                    }

                    @Override
                    public void onError(
                            HibpRangeError serviceError
                    ) {
                        error.set(
                                serviceError
                        );
                    }
                }
        );

        assertNull(
                error.get()
        );

        assertNotNull(
                result.get()
        );

        assertEquals(
                0,
                result.get().size()
        );
    }

    @Test
    public void fetchEntries_emptyResponse_returnsInvalidResponseError() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        ""
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertNotNull(
                error.get()
        );

        assertEquals(
                HibpRangeError.Type.INVALID_RESPONSE,
                error.get().getType()
        );
    }

    @Test
    public void fetchEntries_blankResponse_returnsInvalidResponseError() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        "   \r\n\t   \n"
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertNotNull(
                error.get()
        );

        assertEquals(
                HibpRangeError.Type.INVALID_RESPONSE,
                error.get().getType()
        );
    }

    @Test
    public void fetchEntries_invalidResponse_returnsInvalidResponseError() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.success(
                        "NOT_A_VALID_HIBP_RESPONSE"
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertNotNull(
                error.get()
        );

        assertEquals(
                HibpRangeError.Type.INVALID_RESPONSE,
                error.get().getType()
        );
    }

    @Test
    public void fetchEntries_timeout_returnsTimeoutError() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new SocketTimeoutException(
                                "timeout"
                        )
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertEquals(
                HibpRangeError.Type.TIMEOUT,
                error.get().getType()
        );
    }

    @Test
    public void fetchEntries_httpFailure_returnsHttpErrorWithStatus() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new HibpHttpException(
                                403
                        )
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertEquals(
                HibpRangeError.Type.HTTP_ERROR,
                error.get().getType()
        );

        assertEquals(
                403,
                error.get()
                        .getHttpStatusCode()
        );
    }

    @Test
    public void fetchEntries_ioFailure_returnsNetworkError() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new IOException(
                                "network unavailable"
                        )
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertEquals(
                HibpRangeError.Type.NETWORK_ERROR,
                error.get().getType()
        );
    }

    @Test
    public void fetchEntries_unknownFailure_returnsUnknownError() {

        FakeHibpRangeSource source =
                FakeHibpRangeSource.failure(
                        new Exception(
                                "unexpected"
                        )
                );

        HibpRangeService service =
                new HibpRangeService(
                        source
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "ABCDE",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertEquals(
                HibpRangeError.Type.UNKNOWN,
                error.get().getType()
        );
    }

    @Test
    public void fetchEntries_sourceRejectsPrefix_returnsInvalidRequest() {

        HibpRangeSource rejectingSource =
                new HibpRangeSource() {

                    @Override
                    public void fetchRange(
                            String hashPrefix,
                            Callback callback
                    ) {
                        throw new IllegalArgumentException(
                                "invalid prefix"
                        );
                    }
                };

        HibpRangeService service =
                new HibpRangeService(
                        rejectingSource
                );

        AtomicReference<HibpRangeError> error =
                new AtomicReference<>();

        service.fetchEntries(
                "BAD",
                new ErrorCapturingCallback(
                        error
                )
        );

        assertEquals(
                HibpRangeError.Type.INVALID_REQUEST,
                error.get().getType()
        );
    }

    private static final class ErrorCapturingCallback
            implements HibpRangeService.Callback {

        private final AtomicReference<HibpRangeError> error;

        private ErrorCapturingCallback(
                AtomicReference<HibpRangeError> error
        ) {
            this.error = error;
        }

        @Override
        public void onSuccess(
                List<HibpRangeEntry> entries
        ) {
            // Not expected in error tests.
        }

        @Override
        public void onError(
                HibpRangeError serviceError
        ) {
            error.set(
                    serviceError
            );
        }
    }

    private static String repeat(
            char character,
            int count
    ) {

        StringBuilder builder =
                new StringBuilder(
                        count
                );

        for (int index = 0;
             index < count;
             index++) {

            builder.append(
                    character
            );
        }

        return builder.toString();
    }
}
