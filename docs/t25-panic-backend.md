# T25 Panic backend: standalone verification stage

This implements the Week 10 test-vault fallback while T26 Decoy lifecycle fixes
and T35 application integration are pending. It does not enable Panic mode in
the running application. No Application, Settings or Sign In code is changed.
T25 remains in progress until the integration below is completed and verified.

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
factory only: production code does not call it yet. All existing producers must
be stopped before its targets may be used.

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

## Required integration before marking T25 complete

1. Finish and merge the reviewed T26 lifecycle fixes. Use one `PanicWorkGate`
   for the entire application vault runtime, including always-present Decoy
   initialization, both enrollment/unlock paths, biometric/TOTP work, recovery,
   password changes, queued opens and every background data write. An operation
   remains owned until its actual background work and key use finish, even if
   its UI request was cancelled. Do not release it merely because a callback was
   posted. Invalidate or reject all old callbacks and session claims.
2. Implement `PanicWipeCoordinator.Runtime` against the real session manager
   and both coordinators. Lock and clear displayed data immediately, invalidate
   pending authorization, drain/cancel workers and synchronously confirm closure
   and in-memory key cleanup. The existing asynchronous `closeVault()` and
   `shutdown()` methods are not a complete adapter by themselves. Do not wait on
   Android's main thread or while holding a lock needed by a finishing worker.
3. Before constructing/opening vaults at application startup, recover any
   pending marker. Recovery errors keep authentication and fresh vault creation
   unavailable. After successful cleanup, construct a new runtime for fresh
   setup; never reopen the stopped one or restore a saved unlocked Activity.
4. Implement the enrollment authority using a fully authenticated REAL session,
   completed TOTP where configured, verified actual master/Decoy credentials and
   current session plus credential-configuration generations. Commit while that
   authorization is still current. Require explicit Settings warning and
   confirmation before enrollment. Hide Panic/Decoy settings in the Decoy vault.
5. Preserve three-way separation during all later master/Decoy/Panic setup and
   password changes. Use `isReservedPassword()` and the other role verifiers
   inside the same configuration authorization; checking before an unguarded
   asynchronous save is insufficient.
6. Complete the single shared Sign In router, including uniform role checking
   and timing for configured/unconfigured master, Decoy and Panic roles. This
   backend does not implement that timing policy. Avoid early-return routing
   from `checkAndWipe()` before the uniform role checks have finished. A Panic
   trigger must never claim an unlocked session or bypass TOTP for a normal
   vault. Clear old screens and route to fresh setup only after wipe success.
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
The isolated session/authority adapter is a test double; these are not end-to-end
production Sign In, TOTP, Settings or Decoy switching tests.

First verification on the working branch:

```powershell
.\gradlew.bat :app:testDebugUnitTest :app:assembleDebug :app:lintDebug :app:connectedDebugAndroidTest --console=plain
```

The development host has no Android SDK/emulator. Local Java compilation uses
Android/SQLCipher API stubs; deterministic local lifecycle tests substitute the
crypto port. The Argon2id implementation and all Android persistence/Keystore/
SQLCipher behavior must pass the project's Gradle and device tests before any
verified-backend claim is made.

Android API references used for the storage adapter:
- https://developer.android.com/reference/android/util/AtomicFile
- https://developer.android.com/reference/android/content/Context
- https://developer.android.com/privacy-and-security/keystore
