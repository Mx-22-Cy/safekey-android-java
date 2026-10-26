# T25 Panic backend: role checks, verified trigger, enrollment and recovery

The isolated backend is now joined to the application's real and Decoy runtime
through one captured `PanicRuntimeScope` and work gate. The application exposes
a terminal shutdown adapter; normal authentication remains available until a
verified trigger explicitly stops that runtime. Startup now checks the durable
marker before constructing vaults. Pending cleanup runs on a separate worker;
failed cleanup prevents authentication and fresh setup. The concrete enrollment
backend is wired through `SafeKeyApplication.getPanicBackend()`. Its enrollment
checkpoint passed Android verification (484 unit and 225 instrumented tests).
The shared password-role checks and verified-trigger API are now implemented; their
Android verification is required for this checkpoint. Setup/change collision guards
are the subsequent T25 step.
Hind owns the confirmation/Settings screens and shared Sign In UI integration
(T27/T38), followed by full UI-flow testing. Those screens are not part of this
backend patch. T25 is still in progress and the PR remains Draft.

## Implemented behavior

- Panic enrollment requires a valid confirmed password and three different
  master, Decoy and Panic passwords. It uses the existing master-password
  length/common-pattern policy. Enrollment delegates actual master/Decoy
  reauthentication and completed real-session/TOTP authorization to an authority
  port, with an atomic generation-bound commit.
- The Panic proof uses the existing Argon2id parameters, an independent random
  salt and AES-GCM nonce, and a Panic-specific authenticated context. Passwords
  and derived keys are not persisted. Temporary service copies are cleared;
  callers remain responsible for clearing their own input arrays and UI fields.
- A non-destructive reserved-password check is available for future master and
  Decoy enrollment/change flows. A classifier exception must abort routing;
  it must not be converted into a normal non-match or disabled Panic state.
- A verified Panic trigger permanently stops its runtime's work gate, locks the
  session, arms a durable recovery marker, drains accepted work and closes the
  runtime before deleting anything. A close queued for later is insufficient.
- Cleanup attempts every owned resource, verifies absence, and reports any
  failure. A failed or interrupted wipe retains recovery state. Recovery does
  not require the Panic password again, because the original trigger already
  authorized the wipe. The old runtime never becomes usable again.
- Partial/corrupted marker artifacts require recovery. Missing proof means
  unconfigured; malformed/unreadable proof raises an error. A corrupt proof or
  an incorrect candidate never authorizes a fresh wipe.

## Exact resource manifest

`PanicWipeTargets.forSafeKey()` lists the known owned resources below. It is a
factory called by cold-start recovery only after its empty runtime is stopped.
All existing producers must be stopped before its targets may be used.

| Resource | Cleanup |
| --- | --- |
| `safekey.db`, `safekey_secondary.db` | Database file plus `-wal`, `-shm`, `-journal` |
| Real, Decoy and biometric key-envelope preferences | Clear cached values, remove XML and `.bak`, verify both |
| `safekey_totp_state.enc` | No-backup file plus `.bak` and `.new` |
| `safekey_biometric_vault_key`, `safekey_totp_state_key_v1` | Delete these exact Android Keystore aliases and verify absence |
| `safekey_panic_password.enc` | No-backup proof plus `.bak` and `.new` |
| `safekey_panic_wipe.pending` | Keep until all cleanup verifications pass, then remove its atomic artifacts |

The manifest does not enumerate unrelated files or Keystore aliases. Add any
new recovery/enrollment artifacts explicitly when integrating their owners.
Cleanup means removal of app-owned files, envelopes and keys; it does not
promise physical overwriting of flash storage or removal of off-device copies.

## Backend completion and UI handoff

1. The merged T26 backend and real coordinator now share the application-owned
   runtime scope. Security and database queues count accepted work until its
   `finally` completes. Retained envelope/TOTP adapters reject old-runtime writes.
   TOTP setup, biometric prompt keys, key handoffs and queued result callbacks are
   cancelled and cleared on the UI thread; sensitive screens clear their pending
   input and finish. Extend this ownership to future recovery/UI producers.
2. `SafeKeyApplication.getPanicShutdownRuntime()` supplies the real shutdown
   adapter. Use its scope's gate for the password service and wipe coordinator;
   an unrelated gate is rejected. UI cancellation and session invalidation run
   before the background drain. Terminal database closure is queued on each
   database worker, then all registered workers must terminate and all database
   connections must report closed. Existing asynchronous `closeVault()` and
   `shutdown()` alone are not used as evidence of completion. Never call the
   destructive primitive on the main thread or on a counted vault worker; the
   Panic control worker must not wait for its own operation. A cancellation or closure failure
   keeps the stopped runtime unusable and must retain pending recovery state.
3. Startup probes the marker before database initialization. Pending cleanup
   runs on an independent worker using the exact manifest and shutdown adapter.
   Screen lifecycle bodies are guarded before their initialization, including
   restored protected screens. Failure leaves authentication and setup unavailable.
   Success replaces the stopped scope and clears the old task before fresh setup.
   Normal startup with no marker performs no wipe. Device/process-relaunch
   verification of this integrated path is still required.
4. `AndroidPanicEnrollmentAuthority` verifies a completed Real unlock/session
   claim, the same TOTP configuration, the actual current master and configured
   Decoy credentials, and the current session/vault/configuration generations.
   It never opens the Decoy database to verify that password. A grant is single
   use, expires after 60 seconds, and rejects lock, closure, reauthentication,
   runtime shutdown and credential changes. Enrollment copies clear before the
   counted worker exits. The shared credential lock protects final persistence;
   no persistence monitor is held while awaiting the UI commit dispatcher.
   Hind's T27 confirmation and T38 Settings UI must provide warning/confirmation
   and hide controls in the Decoy vault.
5. Preserve three-way separation during all later master/Decoy/Panic setup and
   password changes. Use `isReservedPassword()` and the other role verifiers
   inside the same configuration authorization; checking before an unguarded
   asynchronous save is insufficient.
6. `PanicBackend.prepareSignIn()` supplies one single-use, cancellable role-check
   request for Hind's shared Sign In UI. It checks master, Decoy and Panic in a
   fixed order without returning early on a match or an ordinary role-check error.
   Absent roles use a dummy KDF/AEAD check whose result is ignored. Any role error,
   ambiguous match, abandoned request or changed credential snapshot aborts routing.
   This equalizes the number of expensive role checks; it does not promise exact
   constant elapsed time across devices, providers, I/O failures or later UI flows.
   A Panic match stops new work only at the final guarded commit. Inputs and the
   request's verification lease clear before the shutdown drain, and PANIC_WIPED
   is returned only after all cleanup verifications succeed. Do not call the legacy
   `PanicPasswordService.checkAndWipe()` ahead of these role checks. MASTER/DECOY
   results never claim an unlocked session, open a database or bypass required TOTP.
   Hind owns the subsequent coordinator calls and navigation.
7. Verify the exact integrated commit on-device: real/Decoy/TOTP sessions,
   pending real and Decoy enrollment, backgrounding, stale callbacks, switching,
   recovery after process death, all password-change collisions and the full
   existing test suite. Restart recovery tests here use a new coordinator and
   durable files; they do not kill and relaunch the Android application process.

## Tests

The unit tests cover password policy, authorization, input-copy cleanup,
Argon2id/AES-GCM proof behavior, queue draining, callback invalidation and failure
recovery. Instrumented tests use uniquely named SQLCipher databases, preferences,
no-backup files and Android Keystore aliases. They also check retained preference
objects, sidecars, partial atomic writes and preservation of unrelated resources.
The original isolated session/authority adapter is a test double. New runtime
shutdown tests exercise production queues and SQLCipher with uniquely named test
storage and a test UI-clear callback. They cover both database closures, a queued
open before deletion, stopped-store writes and clearing abandoned TOTP setup.
Startup gate tests additionally cover initialization ordering, retained-marker
failures, rejected dispatch and cold cleanup with isolated owned resources.
They are not end-to-end production Sign In, Settings, process-restart or Decoy
switching tests. Android verification of each integration patch is still required.

First verification on the working branch:

```powershell
.\gradlew.bat :app:testDebugUnitTest :app:assembleDebug :app:lintDebug :app:connectedDebugAndroidTest --console=plain
```

The development host has no Android SDK/emulator. Local checks use Java syntax
parsing and selected Android/work-gate API stubs; deterministic local lifecycle tests substitute the
crypto port. The Argon2id implementation and all Android persistence/Keystore/
SQLCipher behavior must pass the project's Gradle and device tests before any
verified-backend claim is made.

Android API references used for the storage adapter:
- https://developer.android.com/reference/android/util/AtomicFile
- https://developer.android.com/reference/android/content/Context
- https://developer.android.com/privacy-and-security/keystore

## Concrete enrollment call for Hind (T27/T38)

1. Require an authenticated Real session. Configure the Decoy credential first,
   then close the Decoy database before returning to Real-vault Settings.
2. Show clear warnings that use of the Panic password deletes app-owned vault
   data and protection keys. Obtain explicit confirmation.
3. Obtain `PanicBackend backend = application.getPanicBackend()` while the runtime
   is ready. Call `backend.prepareEnrollment(master, decoy, panic, confirmation,
   true)` to obtain an `EnrollmentRequest` that copies the inputs immediately.
   Retain the request and call `request.run()` once on a background worker.
   Close the request when the screen is abandoned, or in the worker's `finally`.
   Cancellation rejects a later save; an already executing save finishes before
   cancellation returns. The backend performs actual reauthentication;
   UI visibility or `SafeKeySession.UNLOCKED` alone cannot authorize it.
4. Keep all input values in caller-owned `char[]` and clear them in `finally`.
   Clear input widgets and ignore callbacks for an abandoned/changed screen.
5. Display success only after `request.run()` returns successfully.
   Errors require fresh authorization; no previous grant may be reused.

The backend does not require a second TOTP challenge during this enrollment
because it binds authorization to the completed Real sign-in claim and its
TOTP configuration. If TOTP has been changed since that sign-in, sign in again.
An unclaimed unlock or pending TOTP challenge is insufficient even if a caller
incorrectly marks the shared session unlocked.

New regression tests cover actual master/Decoy reauthentication, claimed and
unclaimed sessions, pending and completed TOTP, configuration changes, closed/
expired grants, input cleanup, canceled pending/running enrollment requests,
single-use submission, and interrupted queued/executing UI commits.
Instrumented enrollment fixtures use isolated database/preferences/file names
and a dedicated TOTP Keystore alias; they never run production wipe targets.

## Fixed T25 backend progress parts

1. Panic proof/wipe/shutdown backend — Done.
2. Startup recovery backend — Done; full UI process-relaunch tests remain T27.
3. Production enrollment authorization — Done; 709 tests passed on API 37.
4. Password identification and verified-trigger API — implemented; Android checks pending.
5. Password separation across setup/change operations — pending.
6. Final backend safety verification, integration documentation and PR review — pending.

Remaining at preparation of this checkpoint: **3 / 6**. Mark part 4 Done only
once the exact checkpoint passes the project's Android verification.


## Shared Sign In backend call for Hind (T27)

1. On the UI thread, complete `prepareForVaultAuthentication()` before accepting a
   new attempt. Close an earlier request on replacement, backgrounding or screen
   abandonment. Call `backend.prepareSignIn(candidate)` while the application
   runtime is available; it copies the supplied `char[]` immediately. Keep the
   original input private; clear it after the chosen coordinator has copied it, or
   in `finally` for NO_MATCH, PANIC_WIPED and errors. Clear caller-owned input and
   screen fields on cancellation/backgrounding as well. The backend clears only
   its own copies.
2. Run `request.run()` on an **independent control worker**, never the main thread
   or an executor registered with the vault runtime. A Panic wipe drains those
   vault executors and must not wait for the worker that is currently calling it.
   Always close the request in `finally`. A canceled unstarted request clears its
   pending input. Canceling during verification rejects the final commit and keeps
   active input tracked until the service clears it. After a verified Panic trigger
   is committed, cleanup is terminal and continues even if its screen disappears.
3. Handle the result:
   - `NO_MATCH`: show the common authentication error; do not open either vault.
   - `MASTER`: use the existing Real coordinator unlock flow, including TOTP and
     its one-time session claim. Role identification alone is not authentication.
   - `DECOY`: use the Decoy coordinator and existing session-bound vault activation.
   - `PANIC_WIPED`: only after successful full cleanup, dispatch
     `application.continueAfterPanicWipe(backend)` on main. It rejects any backend
     other than the stopped application's current, successfully completed backend.
     Startup constructs a fresh scope and requires fresh-setup navigation. Open
     `PanicStartupActivity` with the old task cleared; its existing startup gate
     completes the transition to Sign Up. The old backend/runtime stays stopped.
4. Deliver normal results only to the current attempt. Deliver the terminal wipe
   result through the application-level Sign In controller: shutdown deliberately
   clears/finishes sensitive screens, so a callback that depends on the old Activity
   remaining alive cannot own fresh-setup navigation. On any cleanup error, keep
   authentication blocked and recover the durable marker at startup. Never turn an
   exception into NO_MATCH, an unlocked vault, or a successful reset.

The new 20 unit tests verify role ordering, ambiguous/error rejection, cancellation,
configuration changes, copy lifetime and fail-closed wipe behavior. The 14 new
instrumented tests exercise actual Argon2id/AES-GCM proofs, mapped envelope stores,
missing-role dummy checks, the production shutdown adapter and an isolated resource
manifest. Their database paths contain manifest sentinels; existing runtime tests
cover live SQLCipher closure. These tests do not implement Hind's UI or kill and
relaunch the Android application process. Both remain T27 integration checks.
