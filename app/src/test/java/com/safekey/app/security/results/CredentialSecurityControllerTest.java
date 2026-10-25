package com.safekey.app.security.results;

import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.breach.PasswordBreachResult.Status;
import com.safekey.app.data.model.Credential;

import org.junit.Test;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class CredentialSecurityControllerTest {
    @Test public void lockedSessionDoesNotReadCredentialSource() {
        Fixture f = new Fixture(false, credential(1, "unique", Status.NOT_FOUND));
        f.session = false;
        f.load(false);
        assertEquals(0, f.source.loads);
        assertNotNull(f.error);
        assertNull(f.latest);
        f.controller.close();
    }

    @Test public void homeUsesSavedChecksWithoutNetwork() {
        Fixture f = new Fixture(false, credential(1, "unique", Status.NOT_FOUND));
        f.load(true);
        assertEquals(100, f.latest.getScore());
        assertEquals(0, f.checks.size());
        f.controller.close();
    }

    @Test public void automaticChecksTargetIncompleteRecordsOnly() {
        Fixture f = new Fixture(true, credential(1, "checked", Status.NOT_FOUND),
                credential(2, "new", Status.NOT_CHECKED));
        f.load(true);
        assertEquals(1, f.checks.size());
        assertArrayEquals("new".toCharArray(), f.checks.get(0).owned);
        f.controller.close();
    }

    @Test public void reuseIsExactAndCountsBothCredentials() {
        Fixture f = new Fixture(false, credential(1, "Same", Status.NOT_FOUND),
                credential(2, "Same", Status.NOT_FOUND), credential(3, "same", Status.NOT_FOUND));
        f.load(false);
        assertEquals(2, f.latest.getAtRiskCount());
        assertEquals(33, f.latest.getScore());
        f.controller.close();
    }

    @Test public void strengthWorkingArrayIsClearedEvenWhenEstimatorFails() {
        Fixture f = new Fixture(false, credential(1, "private fixture", Status.NOT_FOUND));
        AtomicReference<char[]> borrowed = new AtomicReference<>();
        f.estimator = value -> { borrowed.set(value); throw new IllegalArgumentException("Fixture"); };
        f.rebuild();
        f.load(false);
        assertArrayEquals(new char[borrowed.get().length], borrowed.get());
        assertFalse(f.latest.hasScore());
        assertEquals(CredentialSecuritySummary.Availability.UNAVAILABLE, f.latest.getAvailability());
        f.controller.close();
    }

    @Test public void stoppingBeforeAnalysisSuppressesDelivery() {
        Fixture f = new Fixture(false, credential(1, "unique", Status.NOT_FOUND));
        f.controller.load(f.listener, false);
        f.main.run();
        f.controller.stop();
        f.drain();
        assertNull(f.latest);
        f.controller.close();
    }

    @Test public void cancelledNetworkResultCannotPersistOrUpdateUi() {
        Fixture f = new Fixture(true, credential(1, "unique", Status.NOT_CHECKED));
        f.load(true);
        Check check = f.checks.get(0);
        f.controller.stop();
        assertArrayEquals(new char[check.owned.length], check.owned);
        int delivered = f.deliveries;
        check.finish(PasswordBreachResult.breached(9));
        f.drain();
        assertEquals(0, f.source.saves);
        assertEquals(delivered, f.deliveries);
        f.controller.close();
    }

    @Test public void previousDatabaseOpeningCannotReceiveLateResult() {
        Fixture f = new Fixture(true, credential(1, "unique", Status.NOT_CHECKED));
        f.load(true);
        f.source.generation++;
        f.checks.get(0).finish(PasswordBreachResult.notFound());
        f.drain();
        assertEquals(0, f.source.saves);
        f.controller.close();
    }

    @Test public void refreshWaitsForPersistenceBeforeBecomingSharedState() {
        Fixture f = new Fixture(true, credential(1, "unique", Status.NOT_CHECKED));
        f.source.delaySave = true;
        f.load(true);
        f.checks.get(0).finish(PasswordBreachResult.breached(11));
        f.drain();
        assertEquals(0, f.latest.getBreachCount());
        assertNotNull(f.source.pendingSave);
        f.source.pendingSave.onSuccess(Status.BREACHED);
        f.drain();
        assertEquals(1, f.latest.getBreachCount());
        assertEquals(11L, f.latest.getItems().get(0).getOccurrences());
        f.controller.close();
    }

    @Test public void changedCredentialReloadsWithoutApplyingStaleResult() {
        Fixture f = new Fixture(true, credential(1, "old", Status.NOT_CHECKED));
        f.source.delaySave = true;
        f.load(true);
        f.checks.get(0).finish(PasswordBreachResult.breached(11));
        f.drain();
        f.source.credentials.set(0, credential(1, "new", Status.NOT_CHECKED));
        f.source.pendingSave.onSuccess(null);
        f.drain();
        assertEquals(2, f.source.loads);
        assertEquals(0, f.latest.getBreachCount());
        assertEquals(Status.NOT_CHECKED, f.latest.getItems().get(0).getBreachStatus());
        f.controller.close();
    }

    @Test public void repeatedCheckClickDoesNotDuplicatePendingRequests() {
        Fixture f = new Fixture(true, credential(1, "unique", Status.NOT_CHECKED));
        f.load(true);
        f.controller.checkAll();
        assertEquals(1, f.checks.size());
        f.controller.close();
    }

    @Test public void invalidSourceDoesNotBecomeEmptyHealthyVault() {
        Fixture f = new Fixture(false, credential(0, "unique", Status.NOT_FOUND));
        f.load(false);
        assertNotNull(f.error);
        assertNull(f.latest);
        f.controller.close();
    }

    @Test public void currentSessionIsRequiredWhenQueuedResultActuallyDelivers() {
        Fixture f = new Fixture(true, credential(1, "unique", Status.NOT_CHECKED));
        f.load(true);
        int delivered = f.deliveries;
        f.checks.get(0).finish(PasswordBreachResult.notFound());
        f.session = false;
        f.drain();
        assertEquals(0, f.source.saves);
        assertEquals(delivered, f.deliveries);
        f.controller.close();
    }

    private static Credential credential(long id, String password, Status status) {
        Credential result = new Credential(id, "Item " + id, "user", password,
                "https://example.com", "Work", "", false, 1L, 1L);
        result.setBreachStatus(status);
        return result;
    }

    private static final class Check {
        final char[] owned;
        final Consumer<PasswordBreachResult> callback;
        Check(char[] owned, Consumer<PasswordBreachResult> callback) {
            this.owned = owned;
            this.callback = callback;
        }
        void close() { Arrays.fill(owned, '\0'); }
        void finish(PasswordBreachResult result) { close(); callback.accept(result); }
    }

    private static final class Fixture {
        final Source source = new Source();
        final ManualExecutor main = new ManualExecutor();
        final ManualExecutor worker = new ManualExecutor();
        final List<Check> checks = new ArrayList<>();
        final boolean checking;
        boolean session = true;
        CredentialSecurityController controller;
        CredentialSecurityController.StrengthEstimator estimator = password -> 4;
        CredentialSecuritySummary latest;
        Exception error;
        int deliveries;
        final CredentialSecurityController.Listener listener = new CredentialSecurityController.Listener() {
            @Override public void onResults(CredentialSecuritySummary value) { latest = value; deliveries++; }
            @Override public void onError(Exception value) { error = value; }
        };
        Fixture(boolean checking, Credential... credentials) {
            this.checking = checking;
            source.credentials.addAll(Arrays.asList(credentials));
            rebuild();
        }
        void rebuild() {
            controller = new CredentialSecurityController(source, (password, callback) -> {
                Check check = new Check(password, callback);
                checks.add(check);
                return check::close;
            }, estimator, worker, main, () -> session, () -> { }, checking);
        }
        void load(boolean refresh) { controller.load(listener, refresh); drain(); }
        void drain() {
            int remaining = 100;
            while (!main.tasks.isEmpty() || !worker.tasks.isEmpty()) {
                if (--remaining == 0) { throw new AssertionError("Queue did not settle"); }
                main.run();
                worker.run();
            }
        }
    }

    private static final class Source implements CredentialSecurityController.Source {
        long generation = 1L;
        int loads;
        int saves;
        boolean delaySave;
        final List<Credential> credentials = new ArrayList<>();
        CredentialSecurityController.Result<Status> pendingSave;
        @Override public long getGeneration() { return generation; }
        @Override public void load(CredentialSecurityController.Result<List<Credential>> callback) {
            loads++;
            callback.onSuccess(new ArrayList<>(credentials));
        }
        @Override public void save(long generation, long id, String password, Status status,
                                   CredentialSecurityController.Result<Status> callback) {
            saves++;
            if (delaySave) { pendingSave = callback; }
            else { callback.onSuccess(status); }
        }
    }

    private static final class ManualExecutor extends AbstractExecutorService {
        final Queue<Runnable> tasks = new ArrayDeque<>();
        boolean shutdown;
        @Override public void execute(Runnable command) { tasks.add(command); }
        void run() { while (!tasks.isEmpty()) { tasks.remove().run(); } }
        @Override public void shutdown() { shutdown = true; }
        @Override public List<Runnable> shutdownNow() { shutdown = true; tasks.clear(); return Collections.emptyList(); }
        @Override public boolean isShutdown() { return shutdown; }
        @Override public boolean isTerminated() { return shutdown && tasks.isEmpty(); }
        @Override public boolean awaitTermination(long timeout, TimeUnit unit) { return isTerminated(); }
    }
}
