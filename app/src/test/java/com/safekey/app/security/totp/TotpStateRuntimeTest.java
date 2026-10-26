package com.safekey.app.security.totp;

import com.safekey.app.security.panic.PanicRuntimeScope;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Arrays;

import static org.junit.Assert.*;

public class TotpStateRuntimeTest {
    @Test public void stoppingRuntimeClearsLoadedStateAndItsUpdatedCopy() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        byte[] input = new byte[TotpState.SECRET_LENGTH_BYTES];
        Arrays.fill(input, (byte) 7);
        TotpState loaded = new TotpState(input, -1L, 0, 0L).bindRuntime(scope);
        TotpState updated = loaded.withVerificationState(1L, 0, 0L);
        byte[] owned = ownedSecret(loaded);
        byte[] updatedOwned = ownedSecret(updated);

        scope.cancelPending();
        scope.closeAndAwait(1_000L);

        assertArrayEquals(new byte[input.length], owned);
        assertArrayEquals(new byte[input.length], updatedOwned);
        assertEquals((byte) 7, input[0]);
        try { loaded.copySecret(); fail("stopped state exposed a secret"); }
        catch (IllegalStateException expected) { }
        assertTrue(scope.areResourcesClosed());
    }

    @Test public void normalCloseClearsStateAndReleasesPendingOwnership() throws Exception {
        PanicRuntimeScope scope = new PanicRuntimeScope();
        TotpState loaded = new TotpState(new byte[TotpState.SECRET_LENGTH_BYTES], -1L, 0, 0L)
                .bindRuntime(scope);
        loaded.close();
        loaded.close();
        scope.getWorkGate().blockNewWork();
        scope.closeAndAwait(1_000L);
        assertTrue(scope.areResourcesClosed());
    }

    private static byte[] ownedSecret(TotpState state) throws Exception {
        Field field = TotpState.class.getDeclaredField("secret");
        field.setAccessible(true);
        return (byte[]) field.get(state);
    }
}
