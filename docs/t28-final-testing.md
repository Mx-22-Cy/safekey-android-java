# T28 — Final testing and fixes

## Table 11 security verification

Source: SDP1 Initial Report, Table 11, printed pages 30–31.
Baseline: `17d5656`, with the two buffer tests added on the T28 branch.
Android evidence: `SafeKey_API_37` emulator, Android 17.

| Threat | Evidence | Result |
|---|---|---|
| Brute-force attack | `Argon2idMasterKeyDeriverTest` checks the configured KDF, salts, and derived keys. `MasterPasswordPolicyTest` checks password length and easily guessed values. | 25/25 passed |
| Device theft | `SafeKeyDatabaseRawKeyInstrumentedTest` checks reopening with the correct key and rejection of a wrong key. `BiometricKeyStoreInstrumentedTest` checks missing-key handling and invalid IV rejection. | 6/6 passed |
| Malware or OS attack | `MasterPasswordChangeRequestTest` checks zeroing of request-owned password arrays. The two new `VaultUnlockGateTest` cases check zeroing of the pending database key and TOTP secret after cancellation and expiry. | Password cleanup suite passed. Both new buffer tests passed. |
| Credential stuffing | `HibpRangeClientTest` checks prefix validation and response-size limits. `PasswordGeneratorTest` checks length limits and selected character types. | 19/19 passed |
| Coercion attack | `DecoyVaultCoordinatorInstrumentedTest` checks isolation of the databases, credentials, secure notes, and passwords. `PanicWipeInstrumentedTest` checks removal of vault data, envelopes, keys, and session state, plus recovery from an interrupted wipe. | 23/23 passed |

## Evidence scope

The buffer tests observe specific app-owned `char[]` and `byte[]` arrays.
The SDP1 report describes vault keys as confined to the TEE. The SDP2
vault-opening path temporarily holds raw key bytes in Java arrays, so the
tested mitigation here is cleanup of those app-owned buffers. Device-theft
results describe the SQLCipher and Keystore behavior observed on the emulator.

## Offline verification

Tested on `SafeKey_API_37` with Airplane Mode enabled and Wi-Fi and mobile data off.

| Check | Observed result |
|---|---|
| Master password sign-in | Passed offline. |
| Credential and secure note storage | Created and edited both items offline. Saved edits were present after locking and signing in again. |
| Master password screening during sign-up | Showed “Online check unavailable” and offered “Continue offline” with a pending check. |
| Saved credential breach refresh | After tapping “CHECK ALL PASSWORDS,” the credential stayed under incomplete checks. Alerts showed “Unable to check password” and “Refresh unavailable. Completed saved checks are kept.” |

## NFR-02 performance

Measured on `SafeKey_API_37` with one warm-up and three timed runs per benchmark.

| Measurement | Minimum | Average | Maximum |
|---|---:|---:|---:|
| Standalone Argon2id key derivation | 440.1 ms | 576.8 ms | 806.4 ms |
| Master password unlock through the database-open callback | 264.9 ms | 319.0 ms | 369.0 ms |
| AES-GCM decryption of one sample field | 0.143 ms | 0.231 ms | 0.371 ms |

All three measured unlocks and sample decryptions were under 2,000 ms.
The unlock interval covers the coordinator call through successful database
open. The decryption interval covers the AES-GCM call for one sample field.
Argon2id was measured in a separate benchmark run.
