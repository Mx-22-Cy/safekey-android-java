package com.safekey.app.security.storage;

/** Non-secret metadata bound to the current key envelope. */
public enum MasterPasswordCheckStatus {
    PENDING,
    CHECKED,
    BREACHED
}
