package com.safekey.app.session.logic;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class SessionNavigationTest {

    @Test
    public void destinationFor_lockedSession_returnsLockScreen() {
        assertEquals(
                SessionDestination.LOCK_SCREEN,
                SessionNavigation.destinationFor(
                        SessionState.LOCKED
                )
        );
    }

    @Test
    public void destinationFor_unlockedSession_returnsHome() {
        assertEquals(
                SessionDestination.HOME,
                SessionNavigation.destinationFor(
                        SessionState.UNLOCKED
                )
        );
    }

    @Test
    public void destinationFor_nullState_throwsException() {
        assertThrows(
                NullPointerException.class,
                () -> SessionNavigation.destinationFor(null)
        );
    }
}
