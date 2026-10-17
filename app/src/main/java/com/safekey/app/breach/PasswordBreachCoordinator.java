package com.safekey.app.breach;

import android.os.Handler;
import android.os.Looper;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Connects the local password-breach checker to the
 * asynchronous HIBP range source.
 *
 * Flow:
 * password -> local SHA-1 preparation -> 5-character prefix
 * -> HIBP range request -> local suffix matching -> result.
 *
 * Raw passwords and complete SHA-1 hashes are never
 * passed to the HIBP range source.
 */
public final class PasswordBreachCoordinator {

    private final HibpRangeSource rangeSource;
    private final ExecutorService workerExecutor;
    private final Executor callbackExecutor;

    private final Set<Request> activeRequests =
            ConcurrentHashMap.newKeySet();

    /**
     * Production constructor.
     *
     * Hashing and response matching run on a worker thread.
     * Final results are delivered on Android's main thread.
     */
    public PasswordBreachCoordinator(
            HibpRangeSource rangeSource
    ) {

        this(
                rangeSource,
                Executors.newSingleThreadExecutor(),
                createMainThreadExecutor()
        );
    }

    /**
     * Test constructor.
     */
    PasswordBreachCoordinator(
            HibpRangeSource rangeSource,
            ExecutorService workerExecutor,
            Executor callbackExecutor
    ) {

        this.rangeSource =
                Objects.requireNonNull(
                        rangeSource,
                        "rangeSource"
                );

        this.workerExecutor =
                Objects.requireNonNull(
                        workerExecutor,
                        "workerExecutor"
                );

        this.callbackExecutor =
                Objects.requireNonNull(
                        callbackExecutor,
                        "callbackExecutor"
                );
    }

    /**
     * Starts one password breach check.
     *
     * The coordinator takes ownership of the supplied
     * password array and clears it after local preparation.
     *
     * The returned Request must be closed when the request
     * is cancelled or the vault/session locks.
     */
    public Request check(
            char[] password,
            Callback callback
    ) {

        Objects.requireNonNull(
                callback,
                "callback"
        );

        Request request =
                new Request(
                        callback,
                        callbackExecutor,
                        activeRequests::remove
                );

        activeRequests.add(
                request
        );

        try {

            workerExecutor.execute(
                    () -> prepareAndStart(
                            password,
                            request
                    )
            );

        } catch (RuntimeException exception) {

            clearPassword(
                    password
            );

            PasswordBreachResult result =
                    request.finishWithoutPrepared(
                            PasswordBreachResult.notChecked()
                    );

            request.dispatch(
                    result
            );
        }

        return request;
    }

    private void prepareAndStart(
            char[] password,
            Request request
    ) {

        if (request.isClosed()) {

            clearPassword(
                    password
            );

            return;
        }

        PreparedPasswordBreachCheck preparedCheck;

        try {

            preparedCheck =
                    PasswordBreachChecker.prepare(
                            password
                    );

        } catch (IllegalArgumentException exception) {

            PasswordBreachResult result =
                    request.finishWithoutPrepared(
                            PasswordBreachResult.error(
                                    PasswordBreachResult.ErrorReason.INVALID_INPUT
                            )
                    );

            request.dispatch(
                    result
            );

            return;

        } catch (RuntimeException exception) {

            PasswordBreachResult result =
                    request.finishWithoutPrepared(
                            PasswordBreachResult.notChecked()
                    );

            request.dispatch(
                    result
            );

            return;

        } finally {

            clearPassword(
                    password
            );
        }

        if (!request.attach(
                preparedCheck
        )) {

            return;
        }

        try {

            rangeSource.fetchRange(
                    preparedCheck.getHashPrefix(),
                    new HibpRangeSource.Callback() {

                        @Override
                        public void onSuccess(
                                String responseBody
                        ) {

                            executeOnWorker(
                                    request,
                                    () -> {

                                        PasswordBreachResult result =
                                                request.complete(
                                                        responseBody
                                                );

                                        request.dispatch(
                                                result
                                        );
                                    }
                            );
                        }

                        @Override
                        public void onError(
                                Exception exception
                        ) {

                            PasswordBreachResult.ErrorReason reason =
                                    mapError(
                                            exception
                                    );

                            executeOnWorker(
                                    request,
                                    () -> {

                                        PasswordBreachResult result =
                                                request.fail(
                                                        reason
                                                );

                                        request.dispatch(
                                                result
                                        );
                                    }
                            );
                        }
                    }
            );

        } catch (IllegalArgumentException exception) {

            PasswordBreachResult result =
                    request.fail(
                            PasswordBreachResult.ErrorReason.INVALID_INPUT
                    );

            request.dispatch(
                    result
            );

        } catch (RuntimeException exception) {

            PasswordBreachResult result =
                    request.fail(
                            PasswordBreachResult.ErrorReason.NETWORK_ERROR
                    );

            request.dispatch(
                    result
            );
        }
    }

    private void executeOnWorker(
            Request request,
            Runnable operation
    ) {

        try {

            workerExecutor.execute(
                    operation
            );

        } catch (RuntimeException exception) {

            request.close();
        }
    }

    private static PasswordBreachResult.ErrorReason mapError(
            Exception exception
    ) {

        if (exception
                instanceof SocketTimeoutException) {

            return PasswordBreachResult.ErrorReason.TIMEOUT;
        }

        if (exception
                instanceof IllegalArgumentException) {

            return PasswordBreachResult.ErrorReason.INVALID_INPUT;
        }

        /*
         * HibpHttpException extends IOException.
         * HTTP failures and other IO failures remain
         * NETWORK_ERROR for the password-check result model.
         */
        if (exception
                instanceof IOException) {

            return PasswordBreachResult.ErrorReason.NETWORK_ERROR;
        }

        return PasswordBreachResult.ErrorReason.NETWORK_ERROR;
    }

    private static void clearPassword(
            char[] password
    ) {

        if (password != null) {

            Arrays.fill(
                    password,
                    '\0'
            );
        }
    }

    private static Executor createMainThreadExecutor() {

        Handler mainHandler =
                new Handler(
                        Looper.getMainLooper()
                );

        return command ->
                mainHandler.post(
                        command
                );
    }

    /**
     * Cancels all pending checks owned by this coordinator
     * and stops its worker executor.
     */
    public void shutdown() {

        for (Request request :
                activeRequests.toArray(
                        new Request[0]
                )) {

            request.close();
        }

        activeRequests.clear();

        workerExecutor.shutdownNow();
    }

    public interface Callback {

        void onResult(
                PasswordBreachResult result
        );
    }

    /**
     * Handle for one pending breach check.
     *
     * Close this object on cancellation or vault lock.
     */
    public static final class Request
            implements AutoCloseable {

        private final Callback callback;
        private final Executor callbackExecutor;
        private final Consumer<Request> terminalListener;

        private PreparedPasswordBreachCheck preparedCheck;

        private boolean cancelled;
        private boolean terminal;

        private Request(
                Callback callback,
                Executor callbackExecutor,
                Consumer<Request> terminalListener
        ) {

            this.callback =
                    callback;

            this.callbackExecutor =
                    callbackExecutor;

            this.terminalListener =
                    terminalListener;
        }

        private synchronized boolean attach(
                PreparedPasswordBreachCheck preparedCheck
        ) {

            Objects.requireNonNull(
                    preparedCheck,
                    "preparedCheck"
            );

            if (cancelled
                    || terminal) {

                preparedCheck.close();

                return false;
            }

            this.preparedCheck =
                    preparedCheck;

            return true;
        }

        private PasswordBreachResult complete(
                String responseBody
        ) {

            PasswordBreachResult result;
            boolean becameTerminal =
                    false;

            synchronized (this) {

                if (cancelled
                        || terminal
                        || preparedCheck == null) {

                    return PasswordBreachResult.notChecked();
                }

                result =
                        preparedCheck.complete(
                                responseBody
                        );

                preparedCheck =
                        null;

                terminal =
                        true;

                becameTerminal =
                        true;
            }

            if (becameTerminal) {

                terminalListener.accept(
                        this
                );
            }

            return result;
        }

        private PasswordBreachResult fail(
                PasswordBreachResult.ErrorReason reason
        ) {

            PasswordBreachResult result;
            boolean becameTerminal =
                    false;

            synchronized (this) {

                if (cancelled
                        || terminal
                        || preparedCheck == null) {

                    return PasswordBreachResult.notChecked();
                }

                result =
                        preparedCheck.fail(
                                reason
                        );

                preparedCheck =
                        null;

                terminal =
                        true;

                becameTerminal =
                        true;
            }

            if (becameTerminal) {

                terminalListener.accept(
                        this
                );
            }

            return result;
        }

        private PasswordBreachResult finishWithoutPrepared(
                PasswordBreachResult result
        ) {

            boolean becameTerminal =
                    false;

            synchronized (this) {

                if (cancelled
                        || terminal) {

                    return PasswordBreachResult.notChecked();
                }

                terminal =
                        true;

                becameTerminal =
                        true;
            }

            if (becameTerminal) {

                terminalListener.accept(
                        this
                );
            }

            return result;
        }

        private void dispatch(
                PasswordBreachResult result
        ) {

            try {

                callbackExecutor.execute(
                        () -> callback.onResult(
                                result
                        )
                );

            } catch (RuntimeException ignored) {

                // Result delivery is no longer possible.
            }
        }

        public synchronized boolean isClosed() {

            return cancelled
                    || terminal;
        }

        @Override
        public void close() {

            PreparedPasswordBreachCheck checkToClose =
                    null;

            boolean notifyTerminal =
                    false;

            synchronized (this) {

                if (cancelled) {
                    return;
                }

                cancelled =
                        true;

                if (preparedCheck != null) {

                    checkToClose =
                            preparedCheck;

                    preparedCheck =
                            null;
                }

                if (!terminal) {

                    terminal =
                            true;

                    notifyTerminal =
                            true;
                }
            }

            if (checkToClose != null) {

                checkToClose.close();
            }

            if (notifyTerminal) {

                terminalListener.accept(
                        this
                );
            }
        }
    }
}