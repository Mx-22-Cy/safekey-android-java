package com.safekey.app.autofill;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebView;

import androidx.test.core.app.ActivityScenario;
import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class AutofillTestLoginInstrumentedTest {

    @Test
    public void testLoginScreenLaunches() {

        try (ActivityScenario<AutofillTestLoginActivity> scenario =
                     ActivityScenario.launch(
                             AutofillTestLoginActivity.class
                     )) {

            scenario.onActivity(activity -> {

                assertNotNull(activity);

                assertFalse(
                        "Login activity should remain open",
                        activity.isFinishing()
                );
            });
        }
    }

    @Test
    public void webViewHasAutofillEnabled() {

        try (ActivityScenario<AutofillTestLoginActivity> scenario =
                     ActivityScenario.launch(
                             AutofillTestLoginActivity.class
                     )) {

            scenario.onActivity(activity -> {

                WebView webView = findWebView(
                        activity.findViewById(android.R.id.content)
                );

                assertNotNull(
                        "WebView must exist",
                        webView
                );

                assertTrue(
                        "WebView must support Autofill",
                        webView.isImportantForAutofill()
                );
            });
        }
    }

    private static WebView findWebView(View view) {

        if (view instanceof WebView) {
            return (WebView) view;
        }

        if (view instanceof ViewGroup) {

            ViewGroup group = (ViewGroup) view;

            for (int i = 0; i < group.getChildCount(); i++) {

                WebView found = findWebView(
                        group.getChildAt(i)
                );

                if (found != null) {
                    return found;
                }
            }
        }

        return null;
    }
}
