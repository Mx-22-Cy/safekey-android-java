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

    /*
     * Registration of a new request and the transition
     * into shutdown are protected by the same lock.
     *
     * Therefore a request is either:
     * 1. fully registered before shutdown begins, so
     *    shutdown will close it, or
     * 2. rejected after shutdown begins, so check()
     *    closes it immediately.
     */
    private final Object lifecycleLock =
            new Object();

    private boolean shuttingDown;

    /*
     * Requests remain active until their callback has
     * actually executed, or until they are cancelled.
     *
     * This allows shutdown() to cancel a completed result
     * that is still waiting in the callback executor.
     */
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
     * password array immediately.
     *
     * The password is cleared after local preparation,
     * or earlier if the request is cancelled/shut down
     * before preparation starts.
     *
     * Registration and shutdown are atomic with respect
     * to each other.
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

        Request request;

        boolean schedulingFailed =
                false;

        synchronized (lifecycleLock) {

            request =
                    new Request(
                            password,
                            callback,
                            callbackExecutor,
                            activeRequests::remove
                    );

            /*
             * Once shutdown has started, no new request
             * may be registered or scheduled.
             *
             * close() clears the caller password even
             * though preparation never started.
             */
            if (shuttingDown) {

                request.close();

                return request;
            }

            /*
             * Add the request while holding the same lock
             * used to start shutdown.
             *
             * If this happens first, shutdown's snapshot
             * must contain this request.
             */
            activeRequests.add(
                    request
            );

            try {

                workerExecutor.execute(
                        () -> prepareAndStart(
                                request
                        )
                );

            } catch (RuntimeException exception) {

                schedulingFailed =
                        true;
            }
        }

        /*
         * Do not invoke callback delivery while holding
         * lifecycleLock.
         */
        if (schedulingFailed) {

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
            Request request
    ) {

        PreparedPasswordBreachCheck preparedCheck;

        try {

            /*
             * Request owns the password array.
             *
             * preparePassword() clears it in all cases.
             * If the request was cancelled before this
             * worker task started, it returns null because
             * close() has already cleared the password.
             */
            preparedCheck =
                    request.preparePassword();

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
        }

        /*
         * null means the request was cancelled before
         * preparation started.
         */
        if (preparedCheck == null) {
            return;
        }

        /*
         * Cancellation can happen after preparation
         * finishes but before the prepared check is
         * attached. attach() closes the prepared hash
         * immediately when that happens.
         */
        if (!request.attach(
                preparedCheck
        )) {

            return;
        }

        /*
         * Avoid starting the request when cancellation
         * happened immediately after attachment.
         */
        if (request.isCancelled()) {
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

            /*
             * If shutdown/cancellation prevents the
             * worker operation from running, closing the
             * request clears any retained prepared hash
             * and suppresses result delivery.
             */
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
         * HibpHttpException is an IOException.
         * HTTP failures and other IO failures remain
         * NETWORK_ERROR in the result model.
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
     * Atomically prevents new request registration,
     * closes every currently registered request, then
     * stops the worker executor.
     *
     * A concurrent check() can no longer fall between
     * the active-request snapshot and shutdownNow().
     */
    public void shutdown() {

        Request[] requestsToClose;

        synchronized (lifecycleLock) {

            if (shuttingDown) {
                return;
            }

            /*
             * This is the shutdown linearization point.
             *
             * After this assignment, check() cannot add
             * another request. A check that reaches the
             * lock later will close its password locally
             * and return a cancelled Request.
             */
            shuttingDown =
                    true;

            requestsToClose =
                    activeRequests.toArray(
                            new Request[0]
                    );
        }

        /*
         * Close outside lifecycleLock to avoid holding the
         * coordinator lock while taking individual Request
         * locks or interacting with terminal listeners.
         */
        for (Request request :
                requestsToClose) {

            request.close();
        }

        /*
         * No new requests can be registered now because
         * shuttingDown is permanently true.
         */
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

        /*
         * The Request owns the password immediately.
         *
         * Keeping it here allows close()/shutdown() to
         * clear it even when its worker task is still
         * queued and never starts.
         */
        private char[] pendingPassword;
        private boolean passwordPending;

        private PreparedPasswordBreachCheck preparedCheck;

        private boolean cancelled;
        private boolean terminal;

        private Request(
                char[] password,
                Callback callback,
                Executor callbackExecutor,
                Consumer<Request> terminalListener
        ) {

            this.pendingPassword =
                    password;

            this.passwordPending =
                    true;

            this.callback =
                    callback;

            this.callbackExecutor =
                    callbackExecutor;

            this.terminalListener =
                    terminalListener;
        }

        /**
         * Prepares the local password hash while the
         * Request owns the password.
         *
         * Synchronization prevents close() from racing
         * with preparation. If cancellation happened
         * before preparation began, null is returned.
         *
         * The password array is always cleared before
         * this method finishes.
         */
        private synchronized PreparedPasswordBreachCheck
        preparePassword() {

            if (cancelled
                    || terminal
                    || !passwordPending) {

                return null;
            }

            try {

                return PasswordBreachChecker.prepare(
                        pendingPassword
                );

            } finally {

                clearPendingPasswordLocked();
            }
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

            synchronized (this) {

                if (cancelled
                        || terminal
                        || preparedCheck == null) {

                    return PasswordBreachResult.notChecked();
                }

                PasswordBreachResult result =
                        preparedCheck.complete(
                                responseBody
                        );

                preparedCheck =
                        null;

                terminal =
                        true;

                /*
                 * Do NOT remove from activeRequests here.
                 *
                 * The result may still be sitting in the
                 * callback executor. Keeping this Request
                 * active allows close()/shutdown() to
                 * suppress that queued delivery.
                 */
                return result;
            }
        }

        private PasswordBreachResult fail(
                PasswordBreachResult.ErrorReason reason
        ) {

            synchronized (this) {

                if (cancelled
                        || terminal
                        || preparedCheck == null) {

                    return PasswordBreachResult.notChecked();
                }

                PasswordBreachResult result =
                        preparedCheck.fail(
                                reason
                        );

                preparedCheck =
                        null;

                terminal =
                        true;

                /*
                 * Removal is deferred until callback
                 * execution for cancellation safety.
                 */
                return result;
            }
        }

        private PasswordBreachResult finishWithoutPrepared(
                PasswordBreachResult result
        ) {

            synchronized (this) {

                if (cancelled
                        || terminal) {

                    return PasswordBreachResult.notChecked();
                }

                clearPendingPasswordLocked();

                terminal =
                        true;

                /*
                 * Keep the Request tracked until callback
                 * execution so shutdown can still suppress
                 * a queued result.
                 */
                return result;
            }
        }

        /**
         * Schedules result delivery.
         *
         * Cancellation is checked when the callback
         * actually executes, not only when it is queued.
         * Therefore close()/shutdown() can suppress a
         * completed BREACHED result that has not yet been
         * delivered to the UI.
         */
        private void dispatch(
                PasswordBreachResult result
        ) {

            try {

                callbackExecutor.execute(
                        () -> {

                            try {

                                /*
                                 * Hold this Request lock while
                                 * deciding whether delivery is
                                 * still allowed.
                                 *
                                 * If close() acquired the lock
                                 * first, cancelled is true and
                                 * this callback is suppressed.
                                 */
                                synchronized (this) {

                                    if (cancelled) {
                                        return;
                                    }

                                    callback.onResult(
                                            result
                                    );
                                }

                            } finally {

                                /*
                                 * A request is no longer active
                                 * only after callback execution
                                 * has occurred or been suppressed.
                                 */
                                terminalListener.accept(
                                        this
                                );
                            }
                        }
                );

            } catch (RuntimeException exception) {

                /*
                 * Callback delivery is impossible.
                 * The sensitive material is already cleared
                 * by the terminal operation, so only remove
                 * the tracking reference.
                 */
                terminalListener.accept(
                        this
                );
            }
        }

        public synchronized boolean isClosed() {

            return cancelled
                    || terminal;
        }

        private synchronized boolean isCancelled() {

            return cancelled;
        }

        /**
         * Cancels this request.
         *
         * This clears either:
         * - the password waiting for preparation, or
         * - the retained prepared full hash.
         *
         * A result already queued for callback delivery
         * will observe cancelled=true when it executes
         * and will therefore be suppressed.
         */
        @Override
        public void close() {

            PreparedPasswordBreachCheck checkToClose =
                    null;

            synchronized (this) {

                if (cancelled) {
                    return;
                }

                cancelled =
                        true;

                terminal =
                        true;

                clearPendingPasswordLocked();

                if (preparedCheck != null) {

                    checkToClose =
                            preparedCheck;

                    preparedCheck =
                            null;
                }
            }

            if (checkToClose != null) {

                checkToClose.close();
            }

            /*
             * Remove immediately on cancellation.
             * Any already queued callback still has this
             * Request object and will check cancelled=true
             * before attempting delivery.
             */
            terminalListener.accept(
                    this
            );
        }

        private void clearPendingPasswordLocked() {

            if (!passwordPending) {
                return;
            }

            clearPassword(
                    pendingPassword
            );

            pendingPassword =
                    null;

            passwordPending =
                    false;
        }
    }
}