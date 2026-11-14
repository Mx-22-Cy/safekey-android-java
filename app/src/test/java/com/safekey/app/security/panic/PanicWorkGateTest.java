package com.safekey.app.security.panic;

import org.junit.Test;

import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.*;

public class PanicWorkGateTest {
    @Test public void currentTicketCommitsAndInvalidatesOtherAcceptedWork() {
        PanicWorkGate gate = new PanicWorkGate();
        try (PanicWorkGate.Operation first = gate.begin();
             PanicWorkGate.Operation other = gate.begin()) {
            gate.blockNewWorkIfCurrent(first.ticket());
            assertTrue(gate.isBlocked());
            assertFalse(first.ticket().isCurrent());
            assertFalse(other.ticket().isCurrent());
            assertThrows(CancellationException.class, gate::begin);
        }
        assertTrue(gate.isIdle());
    }

    @Test public void previouslyStoppedRuntimeCannotBeClaimedAsANewCommit() {
        PanicWorkGate gate = new PanicWorkGate();
        try (PanicWorkGate.Operation operation = gate.begin()) {
            gate.blockNewWork();
            assertThrows(CancellationException.class,
                    () -> gate.blockNewWorkIfCurrent(operation.ticket()));
        }
    }

    @Test public void anotherRuntimeTicketCannotCommitThisGate() {
        PanicWorkGate first = new PanicWorkGate();
        PanicWorkGate second = new PanicWorkGate();
        try (PanicWorkGate.Operation operation = first.begin()) {
            assertThrows(CancellationException.class,
                    () -> second.blockNewWorkIfCurrent(operation.ticket()));
            assertFalse(first.isBlocked());
            assertFalse(second.isBlocked());
            assertTrue(operation.ticket().isCurrent());
        }
    }

    @Test public void concurrentVerifiedAttemptsHaveExactlyOneCommitOwner() throws Exception {
        PanicWorkGate gate = new PanicWorkGate();
        ExecutorService workers = Executors.newFixedThreadPool(2);
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (PanicWorkGate.Operation first = gate.begin();
             PanicWorkGate.Operation second = gate.begin()) {
            Future<Boolean> firstResult = workers.submit(() ->
                    tryCommit(gate, first.ticket(), ready, start));
            Future<Boolean> secondResult = workers.submit(() ->
                    tryCommit(gate, second.ticket(), ready, start));
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            boolean firstCommitted = firstResult.get(10, TimeUnit.SECONDS);
            boolean secondCommitted = secondResult.get(10, TimeUnit.SECONDS);
            assertTrue(firstCommitted ^ secondCommitted);
            assertTrue(gate.isBlocked());
        } finally {
            start.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    private static boolean tryCommit(PanicWorkGate gate, PanicWorkGate.Ticket ticket,
                                     CountDownLatch ready, CountDownLatch start) throws Exception {
        ready.countDown();
        if (!start.await(10, TimeUnit.SECONDS)) { throw new AssertionError("Start was not released."); }
        try {
            gate.blockNewWorkIfCurrent(ticket);
            return true;
        } catch (CancellationException expected) {
            return false;
        }
    }
}
