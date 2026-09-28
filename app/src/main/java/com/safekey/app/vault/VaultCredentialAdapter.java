package com.safekey.app.vault;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.safekey.app.R;
import com.safekey.app.data.model.Credential;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

public class VaultCredentialAdapter
        extends RecyclerView.Adapter<VaultCredentialAdapter.CredentialViewHolder> {

    public enum RiskStatus {
        NONE,
        AT_RISK,
        BREACH
    }

    public interface OnCredentialActionListener {
        void onFavoriteClicked(
                Credential credential,
                int position
        );

        void onRiskClicked(
                Credential credential,
                RiskStatus riskStatus,
                View anchorView
        );

        void onCredentialClicked(
                Credential credential
        );
    }

    private final List<Credential> credentials =
            new ArrayList<>();

    private final List<RiskStatus> riskStatuses =
            new ArrayList<>();

    private final OnCredentialActionListener listener;

    public VaultCredentialAdapter(
            OnCredentialActionListener listener
    ) {
        this.listener = listener;
    }

    public void submitCredentials(
            List<Credential> newCredentials,
            List<RiskStatus> newRiskStatuses
    ) {

        credentials.clear();
        riskStatuses.clear();

        if (newCredentials != null) {
            credentials.addAll(
                    newCredentials
            );
        }

        if (newRiskStatuses != null) {
            riskStatuses.addAll(
                    newRiskStatuses
            );
        }

        while (riskStatuses.size()
                < credentials.size()) {

            riskStatuses.add(
                    RiskStatus.NONE
            );
        }

        notifyDataSetChanged();
    }

    @NonNull
    @Override
    public CredentialViewHolder onCreateViewHolder(
            @NonNull ViewGroup parent,
            int viewType
    ) {

        View view =
                LayoutInflater.from(
                        parent.getContext()
                ).inflate(
                        R.layout.item_vault_credential,
                        parent,
                        false
                );

        return new CredentialViewHolder(
                view
        );
    }

    @Override
    public void onBindViewHolder(
            @NonNull CredentialViewHolder holder,
            int position
    ) {

        Credential credential =
                credentials.get(
                        position
                );

        RiskStatus riskStatus =
                riskStatuses.get(
                        position
                );

        holder.bind(
                credential,
                riskStatus,
                listener
        );
    }

    @Override
    public int getItemCount() {
        return credentials.size();
    }

    static class CredentialViewHolder
            extends RecyclerView.ViewHolder {

        private final ImageView imageLogo;

        private final TextView textLogoFallback;

        private final View riskDot;

        private final TextView textName;

        private final TextView textUsername;

        private final TextView textDomain;

        private final ImageButton buttonFavorite;

        CredentialViewHolder(
                @NonNull View itemView
        ) {

            super(
                    itemView
            );

            imageLogo =
                    itemView.findViewById(
                            R.id.imageCredentialLogo
                    );

            textLogoFallback =
                    itemView.findViewById(
                            R.id.textCredentialLogoFallback
                    );

            riskDot =
                    itemView.findViewById(
                            R.id.viewRiskDot
                    );

            textName =
                    itemView.findViewById(
                            R.id.textCredentialName
                    );

            textUsername =
                    itemView.findViewById(
                            R.id.textCredentialUsername
                    );

            textDomain =
                    itemView.findViewById(
                            R.id.textCredentialDomain
                    );

            buttonFavorite =
                    itemView.findViewById(
                            R.id.buttonFavorite
                    );
        }

        void bind(
                Credential credential,
                RiskStatus riskStatus,
                OnCredentialActionListener listener
        ) {

            String title =
                    safeText(
                            credential.getTitle()
                    );

            String username =
                    safeText(
                            credential.getUsername()
                    );

            String website =
                    safeText(
                            credential.getWebsite()
                    );

            textName.setText(
                    title
            );

            textUsername.setText(
                    username
            );

            textDomain.setText(
                    website
            );

            /*
             * Website icon support will be connected later.
             *
             * Until then, show the first letter of the
             * credential title as a safe fallback.
             */
            imageLogo.setVisibility(
                    View.GONE
            );

            textLogoFallback.setVisibility(
                    View.VISIBLE
            );

            textLogoFallback.setText(
                    firstLetter(
                            title
                    )
            );

            if (credential.isFavorite()) {

                buttonFavorite.setImageResource(
                        R.drawable.ic_vault_star_filled
                );

                buttonFavorite.setContentDescription(
                        itemView.getContext().getString(
                                R.string.vault_unfavorite_content_description
                        )
                );

            } else {

                buttonFavorite.setImageResource(
                        R.drawable.ic_vault_star_outline
                );

                buttonFavorite.setContentDescription(
                        itemView.getContext().getString(
                                R.string.vault_favorite_content_description
                        )
                );
            }

            bindRiskStatus(
                    riskStatus
            );

            buttonFavorite.setOnClickListener(
                    view -> {

                        int adapterPosition =
                                getBindingAdapterPosition();

                        if (adapterPosition
                                == RecyclerView.NO_POSITION) {
                            return;
                        }

                        if (listener != null) {

                            listener.onFavoriteClicked(
                                    credential,
                                    adapterPosition
                            );
                        }
                    }
            );

            riskDot.setOnClickListener(
                    view -> {

                        if (listener == null
                                || riskStatus
                                == RiskStatus.NONE) {
                            return;
                        }

                        listener.onRiskClicked(
                                credential,
                                riskStatus,
                                view
                        );
                    }
            );

            itemView.setOnClickListener(
                    view -> {

                        if (listener != null) {

                            listener.onCredentialClicked(
                                    credential
                            );
                        }
                    }
            );
        }

        private void bindRiskStatus(
                RiskStatus riskStatus
        ) {

            if (riskStatus
                    == RiskStatus.BREACH) {

                riskDot.setVisibility(
                        View.VISIBLE
                );

                riskDot.setBackgroundResource(
                        R.drawable.vault_risk_dot_red
                );

                riskDot.setContentDescription(
                        itemView.getContext().getString(
                                R.string.vault_breach_content_description
                        )
                );

                return;
            }

            if (riskStatus
                    == RiskStatus.AT_RISK) {

                riskDot.setVisibility(
                        View.VISIBLE
                );

                riskDot.setBackgroundResource(
                        R.drawable.vault_risk_dot_amber
                );

                riskDot.setContentDescription(
                        itemView.getContext().getString(
                                R.string.vault_at_risk_content_description
                        )
                );

                return;
            }

            riskDot.setVisibility(
                    View.GONE
            );
        }

        private static String safeText(
                String value
        ) {

            if (value == null) {
                return "";
            }

            return value.trim();
        }

        private static String firstLetter(
                String value
        ) {

            if (value == null
                    || value.trim().isEmpty()) {
                return "?";
            }

            return value
                    .trim()
                    .substring(
                            0,
                            1
                    )
                    .toUpperCase(
                            Locale.ROOT
                    );
        }
    }
}