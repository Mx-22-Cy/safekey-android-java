package com.safekey.app.security.storage;

import org.junit.Test;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class MasterPasswordChangeRequestTest {
    @Test
    public void runtimeStopClearsQueuedPasswordCopiesAndRejectsCommit() throws Exception {
        com.safekey.app.security.panic.PanicRuntimeScope scope =
                new com.safekey.app.security.panic.PanicRuntimeScope();
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(
                new char[]{'a'}, new char[]{'b'}, scope);
        java.lang.reflect.Field field = MasterPasswordChangeRequest.class.getDeclaredField("pending");
        field.setAccessible(true);
        char[][] owned = (char[][]) field.get(request);
        scope.cancelPending();
        assertTrue(request.isCancelled());
        assertNull(request.takePasswords());
        assertArrayEquals(new char[1], owned[0]);
        assertArrayEquals(new char[1], owned[1]);
        assertFalse(request.commit(() -> { throw new AssertionError("Stopped commit"); }));
    }

    @Test
    public void completedRequestCannotCommitAgainInStoppedRuntime() {
        com.safekey.app.security.panic.PanicRuntimeScope scope =
                new com.safekey.app.security.panic.PanicRuntimeScope();
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(
                new char[]{'a'}, new char[]{'b'}, scope);
        assertTrue(request.commit(() -> {}));
        scope.cancelPending();
        assertFalse(request.commit(() -> { throw new AssertionError("Stopped commit"); }));
    }

    @Test
    public void successfulCommitClearsAnyRemainingOwnedCopies() throws Exception {
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(
                new char[]{'a'}, new char[]{'b'});
        java.lang.reflect.Field field = MasterPasswordChangeRequest.class.getDeclaredField("pending");
        field.setAccessible(true);
        char[][] owned = (char[][]) field.get(request);
        assertTrue(request.commit(() -> {}));
        assertNull(request.takePasswords());
        assertArrayEquals(new char[1], owned[0]);
        assertArrayEquals(new char[1], owned[1]);
    }

    @Test
    public void queuedRequestOwnsCopiesIndependentOfCallerClearingArrays() {
        char[] current = "old passphrase".toCharArray();
        char[] next = "new passphrase".toCharArray();
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(current, next);
        Arrays.fill(current, '\0');
        Arrays.fill(next, '\0');
        char[][] owned = request.takePasswords();
        assertArrayEquals("old passphrase".toCharArray(), owned[0]);
        assertArrayEquals("new passphrase".toCharArray(), owned[1]);
        Arrays.fill(owned[0], '\0');
        Arrays.fill(owned[1], '\0');
    }

    @Test
    public void cancellationBeforeWorkerStartsRemovesPendingPasswords() {
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(
                new char[]{'a'}, new char[]{'b'});
        request.close();
        assertNull(request.takePasswords());
        assertTrue(request.isCancelled());
    }

    @Test
    public void cancellationAfterWorkerStartsPreventsCommit() {
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(
                new char[]{'a'}, new char[]{'b'});
        char[][] workerOwned = request.takePasswords();
        request.close();
        assertFalse(request.commit(() -> { throw new AssertionError("Cancelled commit"); }));
        Arrays.fill(workerOwned[0], '\0');
        Arrays.fill(workerOwned[1], '\0');
    }

    @Test
    public void activeRequestCanCommitWithoutChangingCallerArrays() {
        char[] current = new char[]{'a'};
        MasterPasswordChangeRequest request = new MasterPasswordChangeRequest(
                current, new char[]{'b'});
        AtomicBoolean committed = new AtomicBoolean();
        assertTrue(request.commit(() -> committed.set(true)));
        assertTrue(committed.get());
        request.close();
        assertArrayEquals(new char[]{'a'}, current);
    }
}
