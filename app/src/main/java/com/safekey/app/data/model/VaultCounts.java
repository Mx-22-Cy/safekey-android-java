package com.safekey.app.data.model;

/**
 * Immutable vault totals.
 * Contains counts only, without credential or note data.
 * Favorites refer to credentials.
 */
public final class VaultCounts {

    private final long credentialCount;
    private final long favoriteCount;
    private final long secureNoteCount;

    public VaultCounts(
            long credentialCount,
            long favoriteCount,
            long secureNoteCount
    ) {
        if (credentialCount < 0
                || favoriteCount < 0
                || secureNoteCount < 0
                || favoriteCount > credentialCount) {
            throw new IllegalArgumentException("Invalid vault counts.");
        }

        this.credentialCount = credentialCount;
        this.favoriteCount = favoriteCount;
        this.secureNoteCount = secureNoteCount;
    }

    public long getCredentialCount() {
        return credentialCount;
    }

    public long getFavoriteCount() {
        return favoriteCount;
    }

    public long getSecureNoteCount() {
        return secureNoteCount;
    }
}
