package com.safekey.app.vault;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.safekey.app.R;
import com.safekey.app.data.model.SecureNote;

import java.util.ArrayList;
import java.util.List;

public class VaultSecureNoteAdapter
        extends RecyclerView.Adapter<VaultSecureNoteAdapter.NoteViewHolder> {

    public interface OnNoteClickListener {

        void onNoteClicked(
                SecureNote note
        );
    }

    private final List<SecureNote> notes =
            new ArrayList<>();

    private final OnNoteClickListener listener;

    public VaultSecureNoteAdapter(
            OnNoteClickListener listener
    ) {

        this.listener =
                listener;
    }

    public void submitNotes(
            List<SecureNote> newNotes
    ) {

        notes.clear();

        if (newNotes != null) {
            notes.addAll(
                    newNotes
            );
        }

        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public NoteViewHolder onCreateViewHolder(
            @NonNull ViewGroup parent,
            int viewType
    ) {

        View view =
                LayoutInflater
                        .from(
                                parent.getContext()
                        )
                        .inflate(
                                R.layout.item_vault_secure_note,
                                parent,
                                false
                        );

        return new NoteViewHolder(
                view
        );
    }

    @Override
    public void onBindViewHolder(
            @NonNull NoteViewHolder holder,
            int position
    ) {

        SecureNote note =
                notes.get(
                        position
                );

        holder.textNoteTitle.setText(
                note.getTitle()
        );

        holder.textNotePreview.setText(
                note.getContent()
        );

        holder.itemView.setOnClickListener(
                view -> {

                    if (listener != null) {

                        listener.onNoteClicked(
                                note
                        );
                    }
                }
        );
    }

    @Override
    public int getItemCount() {

        return notes.size();
    }

    static class NoteViewHolder
            extends RecyclerView.ViewHolder {

        private final TextView textNoteTitle;
        private final TextView textNotePreview;

        NoteViewHolder(
                @NonNull View itemView
        ) {

            super(
                    itemView
            );

            textNoteTitle =
                    itemView.findViewById(
                            R.id.textNoteTitle
                    );

            textNotePreview =
                    itemView.findViewById(
                            R.id.textNotePreview
                    );
        }
    }
}