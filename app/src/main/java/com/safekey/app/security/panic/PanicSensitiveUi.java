package com.safekey.app.security.panic;

import android.app.Activity;
import android.view.View;

/** UI-thread cancellation registered by each sensitive screen. */
public final class PanicSensitiveUi {
    private PanicSensitiveUi() { }

    public static PanicRuntimeScope.Registration bind(Activity activity, Runnable clear) {
        return PanicRuntimeScope.capture(activity).onStop(() -> {
            try { clear.run(); }
            finally {
                activity.getWindow().getDecorView().setVisibility(View.INVISIBLE);
                activity.finish();
            }
        });
    }
}
