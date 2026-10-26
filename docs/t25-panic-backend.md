# T25 Panic-password backend

This backend verifies Panic enrollment, checks sign-in password roles, stops the
shared vault runtime before deletion, and recovers interrupted cleanup before
vault initialization. Hind's confirmation, Settings and shared Sign In screens
are integrated separately under T27/T38. The APIs are available through
`SafeKeyApplication.getPanicBackend()` while the application runtime is ready.

## Enrollment and password separation

Enrollment requires explicit warning confirmation, a claimed Real-vault session
with all required authentication factors completed, and reauthentication of the
actual current Master and configured Decoy passwords. An open database or an
UNLOCKED flag alone is insufficient. The Decoy database must be closed.

`AndroidPanicEnrollmentAuthority` binds authorization to the session, completed
unlock claim, vault generation, TOTP configuration and credential configuration.
Its grant is single-use, expires after 60 seconds and rejects lock, closure,
reauthentication, configuration changes, cancellation and runtime shutdown.
Panic enrollment/replacement validates confirmation, the existing Master-password
policy, and three-way password separation before its guarded save.

Other supported writes use a `PanicPasswordSeparation` permit:

| Operation | Protection |
| --- | --- |
| `createVaultForEnrollment()` and legacy `createVault()` | Compare against stored Decoy/Panic roles, revalidate configuration and save only if no Real envelope exists |
| `createDecoyVault()` | Compare against Master/Panic roles before modifying the cover database; protect initialization and envelope save |
| `changeMasterPassword()` | Preserve current-password, session and cancellation checks; guard the conditional envelope replacement |
| Panic enrollment/replacement | Actual Master/Decoy reauthentication, confirmation and three-way separation, followed by an atomic authorized save |

The separation check runs off main. Final configuration validation and persistence
share the configuration lock, so a racing update invalidates an earlier permit.
Permits contain no plaintext password or database key, expire after 60 seconds
and cannot be reused. Decoy storage's monitor is acquired before the credential
lock to preserve lock order. The separation permit is not session authorization.
There is currently no Decoy-password-change API; any future rewrap must use a
DECOY permit and its own reauthentication/cancellation authorization.

The Panic proof uses Argon2id with the project's existing parameters, an independent
random salt and nonce, and a purpose-bound AES-GCM authenticated context. Passwords
and derived keys are not persisted. Service-owned copies are cleared before their
counted worker exits. Callers must clear their own arrays and screen fields.

## Shared Sign In contract

`PanicBackend.prepareSignIn(candidate)` copies the input and returns one cancellable
request. Run it on an independent control worker, never the main thread or a vault
executor that shutdown must drain. The backend checks Master, Decoy and Panic in
fixed order, including dummy KDF/AEAD work for absent roles. Dummy results cannot
authorize anything. Ordinary role errors do not skip later checks; any error,
ambiguous match, cancellation or changed configuration aborts routing.

This equalizes the number of expensive role checks. It does not promise constant
elapsed time across devices, providers, I/O failures or subsequent UI flows.

| Result | Meaning |
| --- | --- |
| `NO_MATCH` | No role matched; no vault is opened and nothing is deleted |
| `MASTER` | Continue through the existing Real unlock/TOTP/session-claim flow |
| `DECOY` | Continue through the existing Decoy unlock and session activation |
| `PANIC_WIPED` | Verified Panic cleanup completed and every owned target was verified absent |

Master/Decoy identification is not an unlocked session or a TOTP bypass. The legacy
`PanicPasswordService.checkAndWipe()` is not the shared Sign In entry point. UI code
must not call it ahead of the complete role checks or call the destructive wipe
primitive directly. Full call sequencing is in [the handoff](t25-hind-handoff.md).

## Shutdown, cleanup and recovery

All production vault/security objects capture the application-owned
`PanicRuntimeScope`. Accepted background tasks, pending prompts, key handoffs and
queued callbacks retain ownership until they finish or are cleared. A verified
trigger permanently blocks new work and invalidates old tickets. UI cancellation
and session clearing occur before the drain; inputs and the Sign In verification
lease are released before cleanup waits. A committed trigger remains terminal
even if its originating screen disappears.

The wipe arms a durable pending marker before deletion, waits for accepted work,
closes registered workers and database connections, and verifies closure. It then
attempts every owned target and verifies absence. A queued asynchronous close is
not proof of closure. Failure retains recovery state and leaves the old runtime
unusable. The marker is removed only after successful cleanup verification.

| Exact owned resources | Removal |
| --- | --- |
| `safekey.db`, `safekey_secondary.db` | Base file plus `-wal`, `-shm` and `-journal` |
| `safekey_vault_key_envelope`, `safekey_decoy_vault_key_envelope`, `safekey_biometric_key_envelope` | Clear cached preference values; remove XML and `.bak`; verify both |
| `safekey_totp_state.enc`, `safekey_panic_password.enc` | No-backup file plus `.bak` and `.new` |
| `safekey_biometric_vault_key`, `safekey_totp_state_key_v1` | Delete these exact Android Keystore aliases and verify absence |
| `safekey_panic_wipe.pending` | Retain until cleanup succeeds, then remove its atomic artifacts |

Unrelated files and aliases are not enumerated or deleted. Cleanup removes app-owned
files, envelopes and keys; it does not promise physical overwriting of flash or
removal of off-device copies. No caller-supplied deletion paths are accepted.

Cold startup checks marker artifacts before constructing either vault. Partial or
corrupted markers require recovery. Cleanup runs on a separate worker while
startup and restored-screen guards prevent authentication and setup. Recovery
does not need the Panic password again: the prior durable trigger authorized it.
Success creates a fresh runtime; stopped objects never become usable again.
Normal startup without a marker performs no wipe. Failed live cleanup must remain
blocked until recovery; merely recreating an Activity is not a process restart.

## Verified checkpoint and test limits

Code checkpoint: `2de805420d7caae54385e24dd8a4e01feef23310`.
Included main: `5c6827a10273c679656b285da7d110514ca3fd17`.
The final fetch confirmed main was an ancestor, the working tree was clean and
the branch was synced. The full branch whitespace check passed.

Verification on `SafeKey_API_37`, Android 17/API 37, on 2026-10-26:

| Check | Result |
| --- | --- |
| `:app:testDebugUnitTest` | 524 tests; 0 failures, errors or skips |
| `:app:assembleDebug` | Passed |
| `:app:lintDebug` | Passed |
| `:app:connectedDebugAndroidTest` | 251 tests; 0 failures, errors or skips |

The 775 tests include policy/crypto, authorization, separation races, input cleanup,
stale callbacks, runtime shutdown, database closure, exact resource deletion and
startup recovery. Device fixtures use isolated storage and Keystore aliases.
The Sign In manifest tests use database-file sentinels; separate runtime tests
exercise live SQLCipher closure. Restart recovery fixtures use durable files and
fresh coordinators; they do not kill and relaunch the application process.

Manual normal startup/navigation and force-stop persistence were checked at the
earlier startup checkpoint. Current full UI enrollment, shared Sign In triggering,
Decoy concealment and process-death/relaunch scenarios remain Hind's T27 integration
tests. The backend test results do not establish those UI flows as complete.

These documentation updates do not change the tested runtime code. Code changes
during review or integration require the relevant checks again.
