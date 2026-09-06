package com.safekey.app.data.model;

public class SecureNote {

    private long id;
    private String title;
    private String content;
    private long createdAt;
    private long updatedAt;

    public SecureNote(
            long id,
            String title,
            String content,
            long createdAt,
            long updatedAt
    ) {
        this.id = id;
        this.title = title;
        this.content = content;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
    }

    public SecureNote(
            String title,
            String content
    ) {
        this(
                0,
                title,
                content,
                System.currentTimeMillis(),
                System.currentTimeMillis()
        );
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

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
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