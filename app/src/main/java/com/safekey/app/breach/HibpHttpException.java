package com.safekey.app.breach;

import java.io.IOException;

/**
 * Represents a non-success HTTP response returned
 * by the HIBP Pwned Passwords service.
 */
public final class HibpHttpException extends IOException {

    private final int statusCode;

    public HibpHttpException(
            int statusCode
    ) {
        super(
                "HIBP request failed with HTTP "
                        + statusCode
                        + "."
        );

        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }
}
