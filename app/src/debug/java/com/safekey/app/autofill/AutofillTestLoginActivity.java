package com.safekey.app.autofill;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.LinearLayout;
import android.widget.TextView;

public final class AutofillTestLoginActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(24, 40, 24, 24);

        TextView title = new TextView(this);
        title.setText("SafeKey Autofill Test");
        title.setTextSize(22);

        layout.addView(title);

        WebView webView = new WebView(this);

        // Enable Autofill participation for this debug test.
        webView.setImportantForAutofill(
                View.IMPORTANT_FOR_AUTOFILL_YES
        );

        // JavaScript is enabled only for the debug test screen.
        webView.getSettings().setJavaScriptEnabled(true);

        // Focus the username field after the page finishes loading.
        webView.setWebViewClient(new WebViewClient() {

            @Override
            public void onPageFinished(
                    WebView view,
                    String url
            ) {
                super.onPageFinished(view, url);

                view.evaluateJavascript(
                        "(function() {"
                                + "var field = document.querySelector("
                                + "'input[name=\"username\"]');"
                                + "if (field) { field.focus(); }"
                                + "})();",
                        null
                );
            }
        });

        String html =
                "<!DOCTYPE html>"
                        + "<html>"
                        + "<head>"
                        + "<meta name='viewport' "
                        + "content='width=device-width'>"
                        + "</head>"
                        + "<body>"
                        + "<h2>Test Login</h2>"
                        + "<form>"
                        + "<label>Username</label><br>"
                        + "<input type='text' "
                        + "name='username' "
                        + "autocomplete='username'><br><br>"
                        + "<label>Password</label><br>"
                        + "<input type='password' "
                        + "name='password' "
                        + "autocomplete='current-password'><br><br>"
                        + "<button type='button'>Login</button>"
                        + "</form>"
                        + "</body>"
                        + "</html>";

        // Use a test website origin, not a real account.
        webView.loadDataWithBaseURL(
                "https://example.com/",
                html,
                "text/html",
                "UTF-8",
                null
        );

        layout.addView(
                webView,
                new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        0,
                        1
                )
        );

        setContentView(layout);
    }
}
