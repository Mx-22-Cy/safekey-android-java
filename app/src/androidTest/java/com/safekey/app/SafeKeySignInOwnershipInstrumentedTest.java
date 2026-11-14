package com.safekey.app;

import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.auth.SignInController;
import com.safekey.app.security.panic.PanicBackend;
import com.safekey.app.security.panic.PanicRuntimeScope;
import com.safekey.app.security.panic.PanicStartupGate;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

/** Application ownership contracts only. No authentication or wipe is submitted. */
@RunWith(AndroidJUnit4.class)
public final class SafeKeySignInOwnershipInstrumentedTest {
    private SafeKeyApplication application;

    @Before public void setUp() {
        application = (SafeKeyApplication) InstrumentationRegistry.getInstrumentation()
                .getTargetContext().getApplicationContext();
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() ->
                assertTrue("Application startup must finish before this test.",
                        application.isStartupRuntimeAvailable()));
    }

    @Test public void applicationReturnsOneSharedControllerForItsRuntime() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            SignInController first = application.getSignInController();
            assertNotNull(first);
            assertSame(first, application.getSignInController());
        });
    }

    @Test public void screensMustBorrowTheControllerOnTheMainThread() {
        assertNotSame(Looper.getMainLooper(), Looper.myLooper());
        assertThrows(IllegalStateException.class, () -> application.getSignInController());
    }

    @Test public void unverifiedCompletionCannotReplaceTheCurrentRuntime() {
        InstrumentationRegistry.getInstrumentation().runOnMainSync(() -> {
            PanicBackend backend = application.getPanicBackend();
            PanicRuntimeScope scope = application.getPanicRuntimeScope();
            PanicStartupGate startup = application.getStartupGate();
            SignInController controller = application.getSignInController();
            assertFalse(backend.wasWipeCompleted());
            assertFalse(scope.isStopped());

            application.continueAfterPanicWipe(backend);
            application.continueAfterPanicWipe(null);

            assertSame(backend, application.getPanicBackend());
            assertSame(scope, application.getPanicRuntimeScope());
            assertSame(startup, application.getStartupGate());
            assertSame(controller, application.getSignInController());
            assertTrue(application.isStartupRuntimeAvailable());
        });
    }
}
