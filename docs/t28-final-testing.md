# T28 - Final testing and fixes

## Validation after Week 10 integration

Date: 2026-11-08.
Validated code revision: `ebdece7` on `maryam/week11-t28-final-testing`.
This revision merges `main` at `bbc0e74`, including T39 PR #40.
Android evidence: `SafeKey_API_37` emulator, Android 17 / API 37.

| Check | Result at the validated revision |
|---|---|
| Debug APK build (`assembleDebug`) | Passed |
| Full unit suite (`testDebugUnitTest`) | Passed, including the cancellation and expiry buffer-cleanup tests in `VaultUnlockGateTest` |
| Android test compilation (`compileDebugAndroidTestJavaWithJavac`) | Passed |
| Android Lint (`lintDebug`) | Passed |
| Targeted `SecureVaultCoordinatorInstrumentedTest#measureMasterPasswordUnlockAndDecryption` | 1 passed, with three fresh timing samples |
| NFR-02 two-second timing threshold | One of three measured unlocks exceeded the threshold; performance finding remains open |

The targeted benchmark is the instrumented test rerun for this update. A complete
instrumented-suite pass and a new manual offline run are not claimed here.
Previously reported full-suite REAL-vault authentication and SQLCipher opening
failures remain unresolved; their cause has not been established by these results.

## Current NFR-02 performance evidence

Source requirement: SDP1 Initial Report, NFR-02. Authentication and decryption
operations must complete within two seconds.

Measured at `ebdece7` on 2026-11-08 with one warm-up and three timed runs.
The unlock interval covers the coordinator call through the successful
database-open callback. The decryption interval covers a separate AES-GCM call
on one sample field, using a random test key. These measurements do not include
the full UI interaction or decryption of every stored vault item.

| Run | Master-password unlock (ms) | Sample-field AES-GCM decryption (ms) |
|---|---:|---:|
| 1 | 514.443 | 0.355570 |
| 2 | 712.401 | 0.291265 |
| 3 | 2161.457 | 0.200615 |

| Measurement | Minimum (ms) | Average (ms) | Maximum (ms) |
|---|---:|---:|---:|
| Master-password unlock | 514.443 | 1129.434 | 2161.457 |
| Sample-field AES-GCM decryption | 0.200615 | 0.282483 | 0.355570 |

All three sample-field decryptions were below 2,000 ms. Two of three unlocks
were below 2,000 ms; the third exceeded the threshold by 161.457 ms.
The average unlock being below the threshold does not establish that every
measured unlock met NFR-02.

The JUnit benchmark passed its functional assertions: the vault opened and the
decrypted sample matched the original bytes. It does not assert a two-second
timing limit. Therefore the functional pass and the timing exceedance are
reported separately. The cause of the slow third unlock is undetermined from
this run and remains a performance investigation for review.

## Earlier Table 11 security verification

Source: SDP1 Initial Report, Table 11, printed pages 30-31.
Earlier baseline: `17d5656`, with the two buffer tests added on the T28 branch.
Android evidence: `SafeKey_API_37` emulator, Android 17.
The following table preserves the earlier verification results. The latest full
unit-suite pass is recorded separately above.

| Threat | Evidence | Earlier result |
|---|---|---|
| Brute-force attack | `Argon2idMasterKeyDeriverTest` checks the configured KDF, salts, and derived keys. `MasterPasswordPolicyTest` checks password length and easily guessed values. | 25/25 passed |
| Device theft | `SafeKeyDatabaseRawKeyInstrumentedTest` checks reopening with the correct key and rejection of a wrong key. `BiometricKeyStoreInstrumentedTest` checks missing-key handling and invalid IV rejection. | 6/6 passed |
| Malware or OS attack | `MasterPasswordChangeRequestTest` checks zeroing of request-owned password arrays. The two added `VaultUnlockGateTest` cases check zeroing of the pending database key and TOTP secret after cancellation and expiry. | Password cleanup suite passed. Both added buffer tests passed. |
| Credential stuffing | `HibpRangeClientTest` checks prefix validation and response-size limits. `PasswordGeneratorTest` checks length limits and selected character types. | 19/19 passed |
| Coercion attack | `DecoyVaultCoordinatorInstrumentedTest` checks isolation of the databases, credentials, secure notes, and passwords. `PanicWipeInstrumentedTest` checks removal of vault data, envelopes, keys, and session state, plus recovery from an interrupted wipe. | 23/23 passed |

### Evidence scope

This mapping reports component-level evidence for the threat categories.
The buffer tests observe specific app-owned `char[]` and `byte[]` arrays.
The SDP1 report describes vault keys as confined to the TEE. The SDP2
vault-opening path temporarily holds raw key bytes in Java arrays, so the
tested mitigation here is cleanup of those app-owned buffers. Device-theft
results describe the SQLCipher and Keystore behavior observed on the emulator.

## Earlier offline verification

These are the manual observations previously recorded for the earlier baseline,
on `SafeKey_API_37` with Airplane Mode enabled and Wi-Fi and mobile data off.

| Check | Earlier observed result |
|---|---|
| Master-password sign-in | Passed offline. |
| Credential and secure-note storage | Created and edited both items offline. Saved edits were present after locking and signing in again. |
| Master-password screening during sign-up | Showed "Online check unavailable" and offered "Continue offline" with a pending check. |
| Saved-credential breach refresh | After tapping "CHECK ALL PASSWORDS", the credential stayed under incomplete checks. Alerts showed "Unable to check password" and "Refresh unavailable. Completed saved checks are kept." |

## Earlier NFR-02 performance measurements

These are the earlier measurements retained for traceability, rather than fresh
results at `ebdece7`. They used one warm-up and three timed runs per benchmark
on `SafeKey_API_37`.

| Measurement | Minimum | Average | Maximum |
|---|---:|---:|---:|
| Standalone Argon2id key derivation | 440.1 ms | 576.8 ms | 806.4 ms |
| Master-password unlock through the database-open callback | 264.9 ms | 319.0 ms | 369.0 ms |
| AES-GCM decryption of one sample field | 0.143 ms | 0.231 ms | 0.371 ms |

The earlier unlock and sample-decryption runs were below 2,000 ms. Argon2id
was measured in a separate earlier benchmark run and was not remeasured in
the 2026-11-08 targeted update.

## Remaining validation work

- Investigate the current NFR-02 unlock timing exceedance before marking the performance requirement complete.
- Keep the previously reported full-suite authentication and SQLCipher failures tracked until their cause is established and the combined suite is validated.
- Perform final integrated validation against the remaining Week 11 changes when they are merged, including the applicable offline checks.

The targeted benchmark's setup and teardown delete the selected emulator's
normal `safekey.db` and vault-envelope preferences. Run it only on an emulator
whose SafeKey vault may be discarded.
