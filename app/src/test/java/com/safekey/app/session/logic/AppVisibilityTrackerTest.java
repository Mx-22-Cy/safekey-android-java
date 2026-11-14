package com.safekey.app.session.logic;

import org.junit.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class AppVisibilityTrackerTest {

    @Test
    public void initialProcessStop_doesNotInventAForegroundTransition() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        tracker.onProcessStopped();
        assertFalse(tracker.isForeground());
        assertEquals(0, locks.get());
    }

    @Test
    public void lastNormalActivityStop_locksImmediately() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        assertTrue(tracker.isForeground());
        tracker.onActivityStopped(activity, false);
        assertFalse(tracker.isForeground());
        assertEquals(1, locks.get());
    }

    @Test
    public void overlappingActivityNavigation_remainsForeground() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object first = new Object();
        Object second = new Object();
        tracker.onActivityStarted(first);
        tracker.onActivityStarted(second);
        tracker.onActivityStopped(first, false);
        tracker.onProcessStopped();
        assertTrue(tracker.isForeground());
        assertEquals(0, locks.get());
        tracker.onActivityStopped(second, false);
        assertEquals(1, locks.get());
    }

    @Test
    public void duplicateStart_doesNotKeepAnInvisibleActivityCounted() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        tracker.onActivityStarted(activity);
        tracker.onActivityStopped(activity, false);
        assertEquals(1, locks.get());
        assertFalse(tracker.isForeground());
    }

    @Test
    public void distinctActivitiesWithEqualValues_areCountedSeparately() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object first = new String("same");
        Object second = new String("same");
        tracker.onActivityStarted(first);
        tracker.onActivityStarted(second);
        tracker.onActivityStopped(first, false);
        assertEquals(0, locks.get());
        tracker.onActivityStopped(second, false);
        assertEquals(1, locks.get());
    }

    @Test
    public void configurationReplacement_doesNotLock() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object oldActivity = new Object();
        Object replacement = new Object();
        tracker.onActivityStarted(oldActivity);
        tracker.onActivityStopped(oldActivity, true);
        tracker.onActivityDestroyed(oldActivity, true);
        assertEquals(0, locks.get());
        tracker.onActivityStarted(replacement);
        tracker.onProcessStopped();
        assertTrue(tracker.isForeground());
        assertEquals(0, locks.get());
    }

    @Test
    public void interruptedConfigurationReplacement_processStopLocks() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        tracker.onActivityStopped(activity, true);
        tracker.onProcessStopped();
        assertFalse(tracker.isForeground());
        assertEquals(1, locks.get());
    }

    @Test
    public void duplicateStopAndFallback_doNotRepeatCleanup() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        tracker.onActivityStopped(activity, false);
        tracker.onActivityStopped(activity, false);
        tracker.onActivityDestroyed(activity, false);
        tracker.onProcessStopped();
        tracker.onProcessStopped();
        assertEquals(1, locks.get());
    }

    @Test
    public void unknownActivityStop_doesNotStopTheVisibleActivity() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        tracker.onActivityStarted(new Object());
        tracker.onActivityStopped(new Object(), false);
        tracker.onActivityDestroyed(new Object(), false);
        assertTrue(tracker.isForeground());
        assertEquals(0, locks.get());
    }

    @Test
    public void destructionWithoutStop_releasesTheCountedActivity() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        tracker.onActivityDestroyed(activity, false);
        assertFalse(tracker.isForeground());
        assertEquals(1, locks.get());
    }

    @Test
    public void foregroundReturn_allowsTheNextBackgroundTransition() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(locks::incrementAndGet);
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        tracker.onActivityStopped(activity, false);
        tracker.onActivityStarted(activity);
        tracker.onActivityStopped(activity, false);
        assertEquals(2, locks.get());
    }

    @Test
    public void cleanupFailure_doesNotLeaveTheTrackerForeground() {
        AtomicInteger locks = new AtomicInteger();
        AppVisibilityTracker tracker = new AppVisibilityTracker(() -> {
            locks.incrementAndGet();
            throw new IllegalStateException("Simulated cleanup failure.");
        });
        Object activity = new Object();
        tracker.onActivityStarted(activity);
        assertThrows(IllegalStateException.class,
                () -> tracker.onActivityStopped(activity, false));
        assertFalse(tracker.isForeground());
        tracker.onProcessStopped();
        assertEquals(1, locks.get());
    }
}
