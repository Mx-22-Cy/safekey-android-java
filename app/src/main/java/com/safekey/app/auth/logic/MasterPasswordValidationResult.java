package com.safekey.app.auth.logic;

public enum MasterPasswordValidationResult {
    VALID,
    REQUIRED,
    TOO_SHORT,
    TOO_LONG,
    CONFIRMATION_REQUIRED,
    PASSWORDS_DO_NOT_MATCH
}
