package com.safekey.app.session.logic;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Objects;
import java.util.Set;

/**
 * Application-level visibility bookkeeping. Call from Android's main thread.
 *
 * <p>A normal final Activity stop locks immediately. Configuration recreation
 * is allowed to replace its Activity without locking. ProcessLifecycleOwner's
 * delayed ON_STOP provides the fallback if that replacement never starts.</p>
 */
public final class AppVisibilityTracker {
    private final Set<Object> started =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private final Runnable onBackground;
    private boolean foreground;

    public AppVisibilityTracker(Runnable onBackground) {
        this.onBackground = Objects.requireNonNull(onBackground, "onBackground");
    }

    public void onActivityStarted(Object activity) {
        started.add(Objects.requireNonNull(activity, "activity"));
        foreground = true;
    }

    public void onActivityStopped(Object activity, boolean changingConfigurations) {
        Objects.requireNonNull(activity, "activity");
        if (started.remove(activity) && started.isEmpty() && !changingConfigurations) {
            notifyBackground();
        }
    }

    /** Defensive cleanup if a counted Activity is destroyed without a stop. */
    public void onActivityDestroyed(Object activity, boolean changingConfigurations) {
        onActivityStopped(activity, changingConfigurations);
    }

    public void onProcessStopped() {
        if (started.isEmpty()) {
            notifyBackground();
        }
    }

    public boolean isForeground() {
        return foreground;
    }

    private void notifyBackground() {
        if (foreground) {
            // Change state before cleanup so duplicate/reentrant events are safe.
            foreground = false;
            onBackground.run();
        }
    }
}
