package com.safekey.app.security.panic;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

final class PanicTestSupport {
    static final String MASTER = "Mx8!rv3#Lp9$Kq4@Ft7%";
    static final String DECOY = "Dv7!na2#Wq8$Jt4@Bs9%";
    static final String PANIC = "Px6!mc3#Rs8$Hv2@Ld9%";
    interface Action { void run() throws Exception; }

    static <T extends Throwable> T expect(Class<T> type, Action action) throws Exception {
        try { action.run(); }
        catch (Throwable error) {
            if (type.isInstance(error)) { return type.cast(error); }
            throw new AssertionError("Unexpected failure", error);
        }
        throw new AssertionError("Expected " + type.getSimpleName());
    }

    static char[] chars(String text) { return text.toCharArray(); }
    static void assertCleared(char[] chars) {
        assertNotNull(chars);
        assertArrayEquals(new char[chars.length], chars);
    }

    static final class MemoryJournal implements PanicWipeCoordinator.Journal {
        boolean pending;
        boolean failWrite;
        boolean failRead;
        boolean failClear;
        final List<String> events;
        MemoryJournal(List<String> events) { this.events = events; }
        @Override public boolean isPending() throws Exception {
            if (failRead) { throw new Exception("marker read failure"); }
            return pending;
        }
        @Override public void markPending() throws Exception {
            events.add("mark");
            if (failWrite) { throw new Exception("marker write failure"); }
            pending = true;
        }
        @Override public void clearPending() throws Exception {
            events.add("clear marker");
            if (failClear) { throw new Exception("marker clear failure"); }
            pending = false;
        }
    }

    static final class MemoryRuntime implements PanicWipeCoordinator.Runtime {
        boolean unlocked = true;
        boolean closed;
        boolean failLock;
        boolean failClose;
        final List<String> events;
        MemoryRuntime(List<String> events) { this.events = events; }
        @Override public void lockAndClearSession() throws Exception {
            events.add("lock");
            unlocked = false;
            if (failLock) { throw new Exception("session cleanup failure"); }
        }
        @Override public void closeResources() throws Exception {
            events.add("close");
            if (failClose) { throw new Exception("connection close failure"); }
            closed = true;
        }
        @Override public boolean areResourcesClosed() { return closed; }
    }

    static final class MemoryTarget implements PanicWipeCoordinator.Target {
        boolean present = true;
        boolean failErase;
        boolean leavePresent;
        int eraseCalls;
        int verifyCalls;
        final String name;
        final List<String> events;
        MemoryTarget(String name, List<String> events) { this.name = name; this.events = events; }
        @Override public String name() { return name; }
        @Override public void erase() throws Exception {
            events.add("erase " + name);
            eraseCalls++;
            if (failErase) { throw new Exception("delete failure"); }
            if (!leavePresent) { present = false; }
        }
        @Override public void verifyAbsent() throws Exception {
            events.add("verify " + name);
            verifyCalls++;
            if (present) { throw new Exception("artifact remains"); }
        }
    }

    static final class Fixture {
        final List<String> events = new ArrayList<>();
        final PanicWorkGate gate = new PanicWorkGate();
        final MemoryJournal journal = new MemoryJournal(events);
        final MemoryRuntime runtime = new MemoryRuntime(events);
        final MemoryTarget real = new MemoryTarget("real", events);
        final MemoryTarget decoy = new MemoryTarget("decoy", events);
        PanicWipeCoordinator coordinator(long timeoutMillis) {
            return new PanicWipeCoordinator(gate, journal, runtime,
                    Arrays.asList(real, decoy), timeoutMillis);
        }
    }

    static final class MemoryStore implements PanicPasswordService.Store {
        PanicPasswordCrypto.Record record;
        boolean unreadable;
        int saves;
        @Override public Object transactionLock() { return this; }
        @Override public PanicPasswordCrypto.Record load() throws Exception {
            if (unreadable) { throw new Exception("corrupted proof"); }
            return record;
        }
        @Override public void save(PanicPasswordCrypto.Record record) { this.record = record; saves++; }
    }

    /** Test double only: no claim that these arbitrary records are encrypted. */
    static final class MemoryCrypto implements PanicPasswordService.Crypto {
        final Map<PanicPasswordCrypto.Record, String> proofs = new IdentityHashMap<>();
        Action beforeCreate = () -> { };
        char[] capturedPassword;
        @Override public PanicPasswordCrypto.Record create(char[] password) throws Exception {
            capturedPassword = password;
            beforeCreate.run();
            byte[] bytes = new byte[PanicPasswordCrypto.Record.ENCODED_LENGTH];
            ByteBuffer.wrap(bytes).putInt(1);
            PanicPasswordCrypto.Record record = PanicPasswordCrypto.Record.decode(bytes);
            proofs.put(record, new String(password));
            return record;
        }
        @Override public boolean matches(char[] password, PanicPasswordCrypto.Record record) {
            capturedPassword = password;
            return password != null && new String(password).equals(proofs.get(record));
        }
    }

    static final class Authority implements PanicPasswordService.EnrollmentAuthority {
        long generation;
        boolean unlocked = true;
        boolean closed;
        char[] capturedMaster;
        char[] capturedDecoy;
        @Override public PanicPasswordService.Grant authenticate(char[] master, char[] decoy) {
            capturedMaster = master;
            capturedDecoy = decoy;
            if (!unlocked || !Arrays.equals(chars(MASTER), master)
                    || !Arrays.equals(chars(DECOY), decoy)) {
                throw new SecurityException("Reauthentication failed.");
            }
            long expected = generation;
            return new PanicPasswordService.Grant() {
                @Override public void commitIfCurrent(PanicPasswordService.Commit commit) throws Exception {
                    synchronized (Authority.this) {
                        if (!unlocked || expected != generation) {
                            throw new SecurityException("Stale authorization.");
                        }
                        commit.run();
                    }
                }
                @Override public void close() { closed = true; }
            };
        }
    }
}
