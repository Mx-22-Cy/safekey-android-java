package com.safekey.app.auth;

import android.content.Context;

import com.safekey.app.R;
import com.safekey.app.auth.logic.MasterPasswordPolicy;
import com.safekey.app.auth.logic.MasterPasswordValidationResult;

final class MasterPasswordMessages {
    private MasterPasswordMessages() { }

    static String validation(Context context, MasterPasswordValidationResult result) {
        if (result == null) { return context.getString(R.string.master_password_check_failed); }
        switch (result) {
            case REQUIRED:
                return context.getString(R.string.error_master_password_required);
            case TOO_SHORT:
                return context.getResources().getQuantityString(R.plurals.error_password_too_short,
                        MasterPasswordPolicy.MIN_LENGTH, MasterPasswordPolicy.MIN_LENGTH);
            case TOO_LONG:
                return context.getResources().getQuantityString(R.plurals.error_password_too_long,
                        MasterPasswordPolicy.MAX_LENGTH, MasterPasswordPolicy.MAX_LENGTH);
            case CONFIRMATION_REQUIRED:
                return context.getString(R.string.error_confirmation_required);
            case PASSWORDS_DO_NOT_MATCH:
                return context.getString(R.string.error_passwords_do_not_match);
            case EASILY_GUESSED:
                return context.getString(R.string.master_password_local_rejected);
            default:
                return context.getString(R.string.master_password_check_failed);
        }
    }
}
