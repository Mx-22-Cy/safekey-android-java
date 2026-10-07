package com.safekey.app.breach;

/**
 * Safe, typed error returned by the HIBP range service.
 *
 * UI and breach-check logic can react to the error type
 * without depending directly on networking exceptions.
 */
public final class HibpRangeError {

    public enum Type {
        INVALID_REQUEST,
        TIMEOUT,
        NETWORK_ERROR,
        HTTP_ERROR,
        INVALID_RESPONSE,
        UNKNOWN
    }

    public static final int NO_HTTP_STATUS = -1;

    private final Type type;
    private final int httpStatusCode;

    private HibpRangeError(
            Type type,
            int httpStatusCode
    ) {
        this.type = type;
        this.httpStatusCode = httpStatusCode;
    }

    public static HibpRangeError invalidRequest() {
        return new HibpRangeError(
                Type.INVALID_REQUEST,
                NO_HTTP_STATUS
        );
    }

    public static HibpRangeError timeout() {
        return new HibpRangeError(
                Type.TIMEOUT,
                NO_HTTP_STATUS
        );
    }

    public static HibpRangeError networkError() {
        return new HibpRangeError(
                Type.NETWORK_ERROR,
                NO_HTTP_STATUS
        );
    }

    public static HibpRangeError httpError(
            int statusCode
    ) {
        return new HibpRangeError(
                Type.HTTP_ERROR,
                statusCode
        );
    }

    public static HibpRangeError invalidResponse() {
        return new HibpRangeError(
                Type.INVALID_RESPONSE,
                NO_HTTP_STATUS
        );
    }

    public static HibpRangeError unknown() {
        return new HibpRangeError(
                Type.UNKNOWN,
                NO_HTTP_STATUS
        );
    }

    public Type getType() {
        return type;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }

    public boolean hasHttpStatusCode() {
        return httpStatusCode
                != NO_HTTP_STATUS;
    }
}