package com.safekey.app.security.storage;

/**
 * Storage boundary for a protected vault-key envelope.
 *
 * Week 10 Recovery integration handoff:
 * Recovery code may use this contract to inspect or replace
 * the protected envelope after successful Recovery processing.
 *
 * The contract deliberately does not expose the raw SQLCipher
 * database key. Only already-protected envelope material may be
 * persisted through this interface.
 */
public interface VaultKeyEnvelopeStorage {

    /**
     * Returns true when any envelope material is present.
     *
     * A caller should still call load() to validate that the
     * stored envelope is complete and valid.
     */
    boolean hasEnvelope();

    /**
     * Persists a protected vault-key envelope.
     *
     * This may also be used by a future Recovery flow to replace
     * the existing protected envelope after the database key has
     * been securely re-wrapped.
     */
    void save(
            VaultKeyEnvelope envelope
    );

    /**
     * Loads the currently protected envelope.
     *
     * Returns null when no envelope is stored.
     *
     * The returned object contains only the KDF salt and wrapped
     * database-key material. It does not expose a raw database key.
     */
    VaultKeyEnvelope load();

    /**
     * Removes the stored protected envelope.
     */
    void clear();
}
