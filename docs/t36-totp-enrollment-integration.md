# T36 enrollment interface for T39

Use `SafeKeyApplication.getTotpEnrollmentCoordinator()` from the protected T39 UI. The coordinator is `com.safekey.app.security.totp.TotpEnrollmentCoordinator`.

Setup starts with master-password confirmation in the current REAL vault session. The coordinator verifies the password on its worker before exposing provisioning data. Begin enrollment on the Android main thread. Callbacks from the application-provided coordinator arrive on the main thread.

| Java API | Contract |
| --- | --- |
| `begin(char[] masterPassword, SetupCallback callback)` | Returns a `TotpEnrollmentCoordinator.Setup` handle immediately. Wait for `onReady` before reading the QR/manual secret. |
| `SetupCallback.onReady(Setup setup)` | Password verification and setup preparation succeeded. |
| `SetupCallback.onError(Exception error)` | Password verification, storage, or preparation failed. |
| `getPendingSetup()` | Returns the same active handle, including during preparation. Returns `null` when no active setup remains. |
| `Setup.isReady()` | Indicates whether provisioning data is available. |
| `Setup.isActive()` | Checks whether this pending setup remains active. |
| `Setup.isSessionValid()` | Checks whether its original REAL authentication remains valid. |
| `Setup.getAuthenticatorUri()` | Returns the sensitive `otpauth` provisioning URI for local QR rendering. |
| `Setup.copyBase32Secret()` | Returns an owned `char[]` copy of the manual setup key. |
| `Setup.getRemainingMillis()` | Returns the backend's remaining setup lifetime in milliseconds. Expired setup returns zero while its vault session remains valid. |
| `Setup.getExpiresAtElapsedRealtimeMillis()` | Returns the original deadline in the `SystemClock.elapsedRealtime()` clock domain. |
| `Setup.getRemainingAttempts()` | Returns the remaining confirmation attempts. The initial limit is five. |
| `Setup.confirm(char[] code, ConfirmationCallback callback)` | Submits a code for verification and persistence. One confirmation may be pending at a time. |
| `ConfirmationCallback.onResult(TotpEnrollmentService.Confirmation result, int remainingAttempts)` | Delivers the backend result and updated attempt count. |
| `ConfirmationCallback.onError(Exception error)` | Reports a verification or storage failure. |
| `Setup.close()` | Cancels this pending setup and clears its owned temporary secrets. |
| `cancelPending()` | Cancels the coordinator's current pending setup. Prefer the retained handle's `close()` from the UI. |

The confirmation enum is `com.safekey.app.security.totp.TotpEnrollmentService.Confirmation`.

| Value | UI handling |
| --- | --- |
| `ENABLED` | Enrollment was persisted successfully. Finish the setup flow. |
| `INVALID_CODE` | Show the error and remaining attempts. Reuse the current setup. |
| `EXPIRED` | Show setup expiry and offer a fresh enrollment. |
| `ATTEMPT_LIMIT_REACHED` | Finish the exhausted setup and offer a fresh enrollment. |
| `CANCELLED` | End the inactive setup flow. |
| `ALREADY_CONFIGURED` | Report that TOTP is already configured. |

`TotpEnrollmentCoordinator.SessionInvalidException` identifies lost or changed REAL authentication when an operation is invoked. It extends `IllegalStateException`. A closed or unready setup can also reject a call with `IllegalStateException`. Storage and password failures use the error callbacks.

Pending callbacks are discarded when their setup is cancelled or its authorization is lost. On resume, check the retained handle's `isSessionValid()` and `isActive()`, then reacquire the current handle through `getPendingSetup()`. Protected-screen navigation handles a locked vault. A countdown getter can reject with `SessionInvalidException` when the vault session expires before setup expiry.

Retain one setup for the whole Setup/Verify flow. Reuse `getPendingSetup()` when returning to Setup. Keep callback state in lifecycle-aware UI state during activity recreation. Explicit Cancel or leaving the enrollment flow closes the handle. Navigating between Setup and Verify retains it.

Use the backend's remaining milliseconds for the countdown. The absolute deadline uses `SystemClock.elapsedRealtime()`. Keep that deadline across screen transitions. The five-minute setup lifetime starts when the backend creates the pending secret.

The caller owns the password and code arrays supplied to the coordinator. Clear them after the call returns. Clear a copied manual key after rendering it. Clear displayed secrets and discard QR payload references when the screen stops. Render QR data locally and keep provisioning data out of logs and persistent UI state.

The application invalidates pending enrollment during session cleanup. Confirmation persistence is guarded by the original authentication generation, REAL vault selection, and completed authentication evidence. T36 continues to own code verification, replay state, attempt limits, encrypted persistence, and rollback behavior.
