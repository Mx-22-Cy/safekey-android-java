package com.safekey.app.security.results;

import com.safekey.app.breach.PasswordBreachResult;
import com.safekey.app.data.model.Credential;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.BooleanSupplier;

/**
 * Activity-owned security analysis. The main executor owns records and listeners;
 * strength/reuse analysis runs on the worker. Snapshots contain no passwords.
 */
public final class CredentialSecurityController implements AutoCloseable {
    public interface Result<T> {
        void onSuccess(T value);
        void onError(Exception error);
    }
    public interface Source {
        long getGeneration();
        void load(Result<List<Credential>> callback);
        void save(long generation, long id, String expectedPassword,
                  PasswordBreachResult.Status status, Result<PasswordBreachResult.Status> callback);
    }
    public interface Cancellation { void close(); }
    public interface Checker {
        /** Takes ownership of password and clears it after hashing or cancellation. */
        Cancellation check(char[] password, java.util.function.Consumer<PasswordBreachResult> callback);
    }
    public interface StrengthEstimator { int evaluate(char[] password); }
    public interface Listener {
        void onResults(CredentialSecuritySummary summary);
        void onError(Exception error);
    }

    private final Source source;
    private final Checker checker;
    private final StrengthEstimator estimator;
    private final ExecutorService worker;
    private final Executor main;
    private final BooleanSupplier sessionValid;
    private final Runnable closeChecker;
    private final boolean canCheck;
    private final AtomicLong generation = new AtomicLong();
    private final Map<Long, Record> records = new LinkedHashMap<>();
    private final Map<Long, Cancellation> requests = new HashMap<>();
    private Listener listener;
    private long vaultGeneration;
    private long nextCheck;
    private boolean active;
    private boolean closed;

    public CredentialSecurityController(Source source, Checker checker, StrengthEstimator estimator,
                                        ExecutorService worker, Executor main,
                                        BooleanSupplier sessionValid, Runnable closeChecker,
                                        boolean canCheck) {
        this.source = Objects.requireNonNull(source, "source");
        this.checker = Objects.requireNonNull(checker, "checker");
        this.estimator = Objects.requireNonNull(estimator, "estimator");
        this.worker = Objects.requireNonNull(worker, "worker");
        this.main = Objects.requireNonNull(main, "main");
        this.sessionValid = Objects.requireNonNull(sessionValid, "sessionValid");
        this.closeChecker = Objects.requireNonNull(closeChecker, "closeChecker");
        this.canCheck = canCheck;
    }

    /** Call from the main executor. Home reads saved results; Alerts can refresh. */
    public void load(Listener listener, boolean refresh) {
        if (closed) { throw new IllegalStateException("Security analysis is closed."); }
        stop();
        this.listener = Objects.requireNonNull(listener, "listener");
        active = true;
        if (!sessionValid.getAsBoolean()) {
            active = false;
            this.listener.onError(new IllegalStateException("An unlocked vault session is required."));
            return;
        }
        long token = generation.get();
        long opening = source.getGeneration();
        vaultGeneration = opening;
        Result<List<Credential>> loading = new Result<List<Credential>>() {
            @Override public void onSuccess(List<Credential> value) {
                main.execute(() -> {
                    if (!current(token, opening)) { return; }
                    if (value == null) {
                        fail(token, opening, new IllegalStateException("Credentials were unavailable."));
                        return;
                    }
                    List<Credential> copy = new ArrayList<>(value);
                    try {
                        worker.execute(() -> analyze(copy, token, opening, refresh));
                    } catch (RuntimeException error) {
                        copy.clear();
                        fail(token, opening, error);
                    }
                });
            }
            @Override public void onError(Exception error) {
                main.execute(() -> fail(token, opening, error));
            }
        };
        try { source.load(loading); }
        catch (RuntimeException error) { loading.onError(error); }
    }

    private void analyze(List<Credential> credentials, long token, long opening, boolean refresh) {
        List<Record> analyzed = new ArrayList<>();
        Map<String, Integer> passwords = new HashMap<>();
        Set<Long> ids = new HashSet<>();
        try {
            for (Credential credential : credentials) {
                if (generation.get() != token || source.getGeneration() != opening) { return; }
                if (credential == null || credential.getId() <= 0L || !ids.add(credential.getId())) {
                    throw new IllegalStateException("Invalid credential identifiers.");
                }
                String password = credential.getPassword();
                if (password != null && !password.isEmpty()) {
                    passwords.put(password, passwords.getOrDefault(password, 0) + 1);
                }
            }
            for (Credential credential : credentials) {
                if (generation.get() != token || source.getGeneration() != opening) { return; }
                Record record = new Record(credential);
                record.missing = record.password == null || record.password.isEmpty();
                record.score = record.missing ? 0 : -1;
                if (!record.missing) {
                    record.reused = passwords.get(record.password) > 1;
                    char[] working = record.password.toCharArray();
                    try {
                        int measured = estimator.evaluate(working);
                        record.score = measured >= 0 && measured <= 4 ? measured : -1;
                    } catch (RuntimeException unavailable) {
                        record.score = -1;
                    } finally { Arrays.fill(working, '\0'); }
                }
                if (!canCheck) { record.password = null; }
                analyzed.add(record);
            }
            if (generation.get() != token || source.getGeneration() != opening) { return; }
            List<Record> ready = new ArrayList<>(analyzed);
            main.execute(() -> {
                if (!current(token, opening)) { release(ready); return; }
                for (Record record : ready) { records.put(record.id, record); }
                publish();
                if (refresh && canCheck) { startChecks(true); }
            });
        } catch (RuntimeException error) {
            release(analyzed);
            main.execute(() -> fail(token, opening, error));
        } finally {
            passwords.clear();
            credentials.clear();
            if (generation.get() != token || source.getGeneration() != opening) { release(analyzed); }
        }
    }

    public void checkAll() { startChecks(false); }

    private void startChecks(boolean incompleteOnly) {
        long token = generation.get();
        long opening = vaultGeneration;
        if (!canCheck || !current(token, opening)) { return; }
        for (Record record : new ArrayList<>(records.values())) {
            if (record.checking || record.missing || record.password == null) { continue; }
            if (incompleteOnly && (record.status == PasswordBreachResult.Status.BREACHED
                    || record.status == PasswordBreachResult.Status.NOT_FOUND)) { continue; }
            record.checking = true;
            record.refreshFailed = false;
            long check = ++nextCheck;
            record.check = check;
            char[] password = record.password.toCharArray();
            try {
                Cancellation cancellation = Objects.requireNonNull(checker.check(password,
                        result -> main.execute(() -> checked(record, token, opening, check, result))),
                        "cancellation");
                if (current(token, opening) && record.check == check && record.checking) {
                    requests.put(record.id, cancellation);
                } else { cancellation.close(); }
            } catch (RuntimeException error) {
                Arrays.fill(password, '\0');
                record.checking = false;
                record.refreshFailed = true;
            }
        }
        publish();
    }

    private void checked(Record record, long token, long opening, long check,
                         PasswordBreachResult result) {
        if (!current(token, opening) || record.check != check || !record.checking) { return; }
        Cancellation cancellation = requests.remove(record.id);
        if (cancellation != null) { cancellation.close(); }
        if (result == null) {
            record.checking = false;
            record.refreshFailed = true;
            publish();
            return;
        }
        PasswordBreachResult.Status incoming = result.getStatus();
        Result<PasswordBreachResult.Status> persistence =
                new Result<PasswordBreachResult.Status>() {
                    @Override public void onSuccess(PasswordBreachResult.Status saved) {
                        main.execute(() -> {
                            if (!current(token, opening) || record.check != check) { return; }
                            if (saved == null) {
                                Listener retained = listener;
                                load(retained, false);
                                return;
                            }
                            record.status = saved;
                            if (saved == PasswordBreachResult.Status.BREACHED
                                    && incoming == PasswordBreachResult.Status.BREACHED) {
                                record.occurrences = result.getOccurrenceCount();
                            } else if (saved != PasswordBreachResult.Status.BREACHED) {
                                record.occurrences = 0L;
                            }
                            record.checking = false;
                            record.refreshFailed = !result.isChecked();
                            publish();
                        });
                    }
                    @Override public void onError(Exception error) {
                        main.execute(() -> {
                            if (!current(token, opening) || record.check != check) { return; }
                            record.checking = false;
                            record.refreshFailed = true;
                            // Do not present an unpersisted network result as shared state.
                            publish();
                        });
                    }
                };
        try {
            source.save(opening, record.id, record.password, incoming, persistence);
        } catch (RuntimeException error) {
            persistence.onError(error);
        }
    }

    private boolean current(long token, long opening) {
        return active && !closed && generation.get() == token
                && source.getGeneration() == opening && sessionValid.getAsBoolean();
    }

    private void fail(long token, long opening, Exception error) {
        if (current(token, opening) && listener != null) { listener.onError(error); }
    }

    private void publish() {
        if (!current(generation.get(), vaultGeneration) || listener == null) { return; }
        List<CredentialSecurityItem> items = new ArrayList<>();
        for (Record record : records.values()) {
            items.add(new CredentialSecurityItem(record.id, record.title, record.status,
                    record.score, record.reused, record.missing, record.occurrences,
                    record.checking, record.refreshFailed));
        }
        listener.onResults(new CredentialSecuritySummary(items));
    }

    public void stop() {
        active = false;
        generation.incrementAndGet();
        listener = null;
        for (Cancellation request : requests.values()) { request.close(); }
        requests.clear();
        release(new ArrayList<>(records.values()));
        records.clear();
    }

    @Override public void close() {
        if (closed) { return; }
        stop();
        closed = true;
        worker.shutdownNow();
        closeChecker.run();
    }

    private static void release(List<Record> records) {
        for (Record record : records) { record.password = null; }
        records.clear();
    }

    private static final class Record {
        final long id;
        final String title;
        String password;
        PasswordBreachResult.Status status;
        int score;
        boolean missing;
        boolean reused;
        boolean checking;
        boolean refreshFailed;
        long occurrences;
        long check;
        Record(Credential credential) {
            id = credential.getId();
            title = credential.getTitle();
            password = credential.getPassword();
            status = credential.getBreachStatus();
        }
    }
}
