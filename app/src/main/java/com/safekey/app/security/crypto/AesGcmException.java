package com.safekey.app.security.crypto;

public final class AesGcmException
        extends Exception {

    public AesGcmException(
            String message
    ) {
        super(message);
    }

    public AesGcmException(
            String message,
            Throwable cause
    ) {
        super(
                message,
                cause
        );
    }
}
