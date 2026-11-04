# T25 integration handoff for Hind

Maryam's backend supplies Panic enrollment, role checking, verified cleanup,
startup recovery and password-separation guards. Hind owns the T27 confirmation
and shared Sign In screens and T38 Settings hookup. This handoff does not add or
claim completion of those screens.

## Settings and Panic enrollment

1. Configure Decoy first. Return to a fully authenticated Real session and close
   the Decoy database. Hide Panic configuration while the active vault is Decoy.
2. Show the destructive-action warning and obtain explicit confirmation. Collect
   the actual current Master and Decoy passwords, a proposed Panic password and
   its confirmation. Never log these values or put them in an Intent/Bundle.
3. While startup is ready, obtain `PanicBackend backend = app.getPanicBackend()`.
   Call `backend.prepareEnrollment(master, decoy, panic, confirmation, true)` and
   retain its `EnrollmentRequest`. Preparation copies the arrays immediately.
4. Run `request.run()` on a background worker and close the request in `finally`.
   Close it on abandonment/backgrounding and clear caller-owned arrays/widgets.
   Cancellation rejects a later save; a save already executing finishes before
   cancellation returns. Success is shown only after the call returns normally.
5. The backend performs actual reauthentication. A UI flag is insufficient. A
   claimed completed Real unlock is required, including TOTP when configured.
   If TOTP configuration changed since sign-in, sign in again. No extra TOTP
   challenge is required when that original completed authentication is current.

The synchronous convenience call `backend.enrollPanicPassword(...)` is available
for callers that can correctly own its lifetime. Prefer the prepared request for
an Activity that can be abandoned while password work is running.

## Shared Sign In

Use one application-level Sign In controller and one current attempt. Preserve
the existing `app.prepareForVaultAuthentication(...)` readiness barrier before
starting a new attempt. Cancel/close an earlier request when it is replaced.

Prepare `PanicBackend.SignInRequest request = backend.prepareSignIn(candidate)`.
Run `request.run()` on an **independent control worker**, never main or a registered
vault/security executor: a Panic wipe drains those executors. Always close the
request in `finally`. Clear the caller's input when no longer required and on
abandonment; the backend clears its own copy, not every copy the UI creates.

| Result | Controller action |
| --- | --- |
| `NO_MATCH` | Show the common authentication error; open no vault |
| `MASTER` | Call the existing Real unlock flow; complete TOTP if required, claim the successful request once, then unlock/activate Real using current-attempt checks |
| `DECOY` | Call the existing Decoy unlock flow; activate its session only from the still-current successful callback |
| `PANIC_WIPED` | Dispatch the terminal application-level handoff below on main |

The role result alone never authorizes a normal vault session. Do not convert
exceptions into NO_MATCH or fall back to another role after a backend error.
Do not call `checkAndWipe()` first, compare raw password strings in the screen,
or invoke `PanicWipeCoordinator.wipe()` directly.

### Terminal wipe result

Shutdown clears/finishes sensitive screens. Therefore an application-level
controller must own the terminal result; it cannot depend on the source Activity
remaining alive. Keep the backend reference captured for that attempt. After
`PANIC_WIPED`, perform this on the main thread:

```java
app.continueAfterPanicWipe(backend);
Intent next = new Intent(app, PanicStartupActivity.class);
next.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
app.startActivity(next);
```

`continueAfterPanicWipe` accepts only the application's current stopped backend
after verified cleanup. It initializes a fresh scope. The startup screen waits
for readiness and routes to fresh Sign Up; old screens and runtime objects must
not be reused. Once the trigger is committed, closing its screen/request does
not reverse cleanup. A cleanup exception is not a successful reset: retain the
blocked state and pending marker for recovery on a fresh application process.
Simply finishing or reopening an Activity does not create a new process.

## Setup and password changes

Continue using the existing protected coordinator APIs. Both Real setup paths,
Decoy setup and Master-password change now enforce role separation internally.
Panic enrollment/replacement does the same through actual reauthentication and
its atomic grant. No additional UI-only collision comparison is needed.

Preserve strength/breach screening and explicit consent rules. A separation
permit does not replace those rules or authentication. Do not save raw envelopes
or proofs from UI code. A future Decoy-password-change feature needs its own
reauthentication and a DECOY separation permit; it is not currently implemented.

## T27 integration verification after merging the backend

- Distinct enrollment succeeds; wrong actual Master/Decoy credentials, missing
  confirmation and colliding proposed passwords are rejected.
- Decoy mode conceals Panic settings. Normal Master/Decoy routing reaches only
  the intended vault; Master still requires configured TOTP and session claim.
- Wrong passwords, malformed proof/configuration and abandoned/stale attempts
  never unlock a vault or authorize a fresh wipe.
- A valid Panic entry completes cleanup before fresh setup, clears the old task,
  and cannot return to a previous vault through Back or retained callbacks.
- Backgrounding, pending biometric/TOTP work and a canceled confirmation cannot
  save state after the old runtime is stopped.
- On isolated disposable test data, kill the application process during cleanup,
  relaunch, and verify recovery blocks authentication until cleanup succeeds.
  Separately check failed cleanup remains blocked. Activity recreation alone is
  not this test. Never run destructive scenarios with personal vault contents.
- Repeat the existing four Gradle checks after UI integration and test the actual
  integrated commit on the agreed devices.

Baseline backend evidence is recorded in [t25-panic-backend.md](t25-panic-backend.md):
775 passing tests on API 37, build/lint passed, and latest main included at the
reviewed code checkpoint. UI and process-relaunch results must be recorded
separately after integration.
