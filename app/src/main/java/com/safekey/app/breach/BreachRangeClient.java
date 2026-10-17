package com.safekey.app.breach;

/**
 * Connection boundary for Pwned Passwords range requests.
 *
 * Receives only a five-character hexadecimal hash prefix.
 * Returns the complete SHA-1 range response after HTTP 200.
 * Failed requests must throw BreachRangeException.
 *
 * This operation is blocking and must run on a worker thread.
 */
@FunctionalInterface
public interface BreachRangeClient {

    String fetchRange(String hashPrefix) throws BreachRangeException;
}
