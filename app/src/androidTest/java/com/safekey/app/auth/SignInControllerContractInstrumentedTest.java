package com.safekey.app.auth;

import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import android.os.Handler;
import android.os.Looper;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.safekey.app.SafeKeyApplication;
import com.safekey.app.security.panic.PanicBackend;
import com.safekey.app.security.panic.PanicSignInService;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.concurrent.Executor;

/**
 * Non-destructive API contract tests. These intentionally do not submit any
 * authentication or Panic credentials. Full routing tests are still required.
 */
@RunWith(AndroidJUnit4.class)
public final class SignInControllerContractInstrumentedTest {
    private static final class Callback implements SignInController.SignInCallback {
        @Override
        public void onRoleIdentified(PanicSignInService.Result role, char[] password) {
            throw new AssertionError("No role callback expected in this test");
        }

        @Override
        public void onError(Exception error) {
            throw new AssertionError("No error callback expected in this test", error);
        }
    }

    private static final class TerminalHandler implements SignInController.PanicTerminalHandler {
        @Override
        public void onPanicWiped(PanicBackend backend) {
            throw new AssertionError("No Panic wipe expected");
        }

        @Override
        public void onPanicFailed(PanicBackend backend, Exception error) {
            throw new AssertionError("No Panic failure expected", error);
        }
    }

    private static SignInController create() {
        SafeKeyApplication app = (SafeKeyApplication) InstrumentationRegistry
                .getInstrumentation().getTargetContext().getApplicationContext();
        Executor worker = Runnable::run;
        return new SignInController(app, worker,
                new Handler(Looper.getMainLooper()), new TerminalHandler());
    }

    @Test
    public void emptyPasswordIsRejectedBeforeStartingAnyAuthentication() {
        try (SignInController controller = create()) {
            assertThrows(IllegalArgumentException.class,
                    () -> controller.startPasswordSignIn(new char[0], new Callback()));
        }
    }

    @Test
    public void nullInputsAreRejectedBeforeStartingAnyAuthentication() {
        try (SignInController controller = create()) {
            assertThrows(NullPointerException.class,
                    () -> controller.startPasswordSignIn(null, new Callback()));
            assertThrows(NullPointerException.class,
                    () -> controller.startPasswordSignIn(new char[]{'x'}, null));
        }
    }

    @Test
    public void detachedUnknownOwnerDoesNotAffectControllerLifecycle() {
        try (SignInController controller = create()) {
            controller.detachCallback(new Callback());
            controller.cancelCurrentAttempt(new Callback());
            controller.cancelCurrentAttempt();
        }
    }

    @Test
    public void closeIsIdempotentAndRejectsNewAttemptsWithoutMutatingCallerInput() {
        SignInController controller = create();
        controller.close();
        controller.close();
        char[] password = new char[]{'t', 'e', 's', 't'};
        try {
            assertThrows(IllegalStateException.class,
                    () -> controller.startPasswordSignIn(password, new Callback()));
            assertTrue(Arrays.equals(new char[]{'t', 'e', 's', 't'}, password));
        } finally {
            Arrays.fill(password, '\0');
        }
    }
}
