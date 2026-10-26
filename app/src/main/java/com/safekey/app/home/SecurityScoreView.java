package com.safekey.app.home;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

import com.safekey.app.R;

public class SecurityScoreView extends View {

    private final Paint backgroundPaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Paint progressPaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Paint scorePaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Paint labelPaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    // Reused instead of creating a new RectF inside onDraw().
    private final RectF arcBounds = new RectF();

    private boolean scoreAvailable;
    private String unavailableText;
    private int score = 0;
    private String scoreText = "\u2014";
    private String maxScoreText;

    public SecurityScoreView(Context context) {
        super(context);
        initialize();
    }

    public SecurityScoreView(
            Context context,
            AttributeSet attrs
    ) {
        super(context, attrs);
        initialize();
    }

    public SecurityScoreView(
            Context context,
            AttributeSet attrs,
            int defStyleAttr
    ) {
        super(context, attrs, defStyleAttr);
        initialize();
    }

    private void initialize() {

        backgroundPaint.setStyle(Paint.Style.STROKE);
        backgroundPaint.setStrokeWidth(dpToPx(10));
        backgroundPaint.setStrokeCap(Paint.Cap.ROUND);
        backgroundPaint.setColor(
                getContext().getColor(R.color.auth_input_border)
        );

        progressPaint.setStyle(Paint.Style.STROKE);
        progressPaint.setStrokeWidth(dpToPx(10));
        progressPaint.setStrokeCap(Paint.Cap.ROUND);
        progressPaint.setColor(
                getContext().getColor(R.color.auth_accent)
        );

        scorePaint.setTextAlign(Paint.Align.CENTER);
        scorePaint.setTypeface(
                android.graphics.Typeface.DEFAULT_BOLD
        );
        scorePaint.setColor(
                getContext().getColor(R.color.auth_text_primary)
        );
        scorePaint.setTextSize(spToPx(32));

        labelPaint.setTextAlign(Paint.Align.CENTER);
        labelPaint.setColor(
                getContext().getColor(R.color.auth_text_secondary)
        );
        labelPaint.setTextSize(spToPx(11));

        unavailableText = getResources().getString(R.string.security_not_checked);

        maxScoreText =
                getResources().getString(
                        R.string.home_security_score_max
                );

        setImportantForAccessibility(
                IMPORTANT_FOR_ACCESSIBILITY_YES
        );

        updateAccessibilityDescription();
    }

    public void setScore(int score) {
        scoreAvailable = true;

        this.score =
                Math.max(
                        0,
                        Math.min(100, score)
                );

        scoreText =
                Integer.toString(this.score);

        progressPaint.setColor(getContext().getColor(this.score == 100
                ? R.color.auth_accent : R.color.dashboard_warning));
        updateAccessibilityDescription();
        invalidate();
    }

    public void setUnavailable(String description) {
        scoreAvailable = false;
        score = 0;
        scoreText = "\u2014";
        unavailableText = description;
        updateAccessibilityDescription();
        invalidate();
    }

    private void updateAccessibilityDescription() {

        if (!scoreAvailable) {
            setContentDescription(unavailableText);
            return;
        }
        setContentDescription(
                getResources().getString(
                        R.string.home_security_score_accessibility,
                        score
                )
        );
    }

    @Override
    protected void onDraw(Canvas canvas) {

        super.onDraw(canvas);

        float padding = dpToPx(12);

        float size =
                Math.min(
                        getWidth(),
                        getHeight()
                );

        float left =
                (getWidth() - size) / 2f;

        float top =
                (getHeight() - size) / 2f;

        arcBounds.set(
                left + padding,
                top + padding,
                left + size - padding,
                top + size - padding
        );

        canvas.drawArc(
                arcBounds,
                -90,
                360,
                false,
                backgroundPaint
        );

        if (scoreAvailable) {
            canvas.drawArc(arcBounds, -90, 360f * score / 100f, false, progressPaint);
        }

        float centerX =
                getWidth() / 2f;

        float centerY =
                getHeight() / 2f;

        float scoreY =
                centerY
                        - (
                        scorePaint.ascent()
                                + scorePaint.descent()
                ) / 2f
                        - dpToPx(7);

        canvas.drawText(
                scoreText,
                centerX,
                scoreY,
                scorePaint
        );

        canvas.drawText(
                scoreAvailable ? maxScoreText : unavailableText,
                centerX,
                centerY + dpToPx(23),
                labelPaint
        );
    }

    private float dpToPx(float dp) {

        return dp
                * getResources()
                .getDisplayMetrics()
                .density;
    }

    private float spToPx(float sp) {

        return sp
                * getResources()
                .getDisplayMetrics()
                .scaledDensity;
    }
}