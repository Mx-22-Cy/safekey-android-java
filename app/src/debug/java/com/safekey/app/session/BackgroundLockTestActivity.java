package com.safekey.app.session;

import android.os.Bundle;
import android.widget.FrameLayout;

/** Debug-only protected screens for lifecycle tests; no vault data is loaded. */
public class BackgroundLockTestActivity extends ProtectedActivity {
    @Override
    protected void onRuntimeCreate(Bundle state) {
        super.onRuntimeCreate(state);
        setContentView(new FrameLayout(this));
    }

    public static final class Second extends BackgroundLockTestActivity { }
}
