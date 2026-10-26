package com.safekey.app.data.model;

import com.safekey.app.breach.PasswordBreachResult;
import java.util.Objects;

public class Credential {

    private PasswordBreachResult.Status breachStatus = PasswordBreachResult.Status.NOT_CHECKED;

    private long id;
    private String title;
    private String username;
    private String password;
    private String website;
    private String category;
    private String notes;
    private boolean favorite;
    private long createdAt;
    private long updatedAt;

    public Credential(
            long id,
            String title,
            String username,
            String password,
            String website,
            String category,
            String notes,
            boolean favorite,
            long createdAt,
            long updatedAt
    ) {
        this.id = id;
        this.title = title;
        this.username = username;
        this.password = password;
        this.website = website;
        this.category = category;
        this.notes = notes;
        this.favorite = favorite;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public Credential(
            String title,
            String username,
            String password,
            String website,
            String category,
            String notes
    ) {
        this(
                0,
                title,
                username,
                password,
                website,
                category,
                notes,
                false,
                System.currentTimeMillis(),
                System.currentTimeMillis()
        );
    }

    public PasswordBreachResult.Status getBreachStatus() {
        return breachStatus;
    }

    public void setBreachStatus(PasswordBreachResult.Status status) {
        breachStatus = Objects.requireNonNull(status, "status");
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getWebsite() {
        return website;
    }

    public void setWebsite(String website) {
        this.website = website;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getNotes() {
        return notes;
    }

    public void setNotes(String notes) {
        this.notes = notes;
    }

    public boolean isFavorite() {
        return favorite;
    }

    public void setFavorite(boolean favorite) {
        this.favorite = favorite;
    }

    public long getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(long createdAt) {
        this.createdAt = createdAt;
    }

    public long getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(long updatedAt) {
        this.updatedAt = updatedAt;
    }
}