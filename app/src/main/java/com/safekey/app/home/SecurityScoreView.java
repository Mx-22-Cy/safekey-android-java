package com.safekey.app.home;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

public class SecurityScoreView extends View {

    private final Paint backgroundPaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Paint progressPaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Paint scorePaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private final Paint labelPaint =
            new Paint(Paint.ANTI_ALIAS_FLAG);

    private int score = 0;

    public SecurityScoreView(
            Context context
    ) {
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

        backgroundPaint.setStyle(
                Paint.Style.STROKE
        );

        backgroundPaint.setStrokeWidth(
                dpToPx(14)
        );

        backgroundPaint.setStrokeCap(
                Paint.Cap.ROUND
        );

        backgroundPaint.setColor(
                Color.parseColor("#223247")
        );

        progressPaint.setStyle(
                Paint.Style.STROKE
        );

        progressPaint.setStrokeWidth(
                dpToPx(14)
        );

        progressPaint.setStrokeCap(
                Paint.Cap.ROUND
        );

        progressPaint.setColor(
                Color.parseColor("#00FF88")
        );

        scorePaint.setTextAlign(
                Paint.Align.CENTER
        );

        scorePaint.setTypeface(
                android.graphics.Typeface.DEFAULT_BOLD
        );

        scorePaint.setColor(
                Color.WHITE
        );

        scorePaint.setTextSize(
                spToPx(34)
        );

        labelPaint.setTextAlign(
                Paint.Align.CENTER
        );

        labelPaint.setColor(
                Color.parseColor("#8FA1B7")
        );

        labelPaint.setTextSize(
                spToPx(12)
        );
    }

    public void setScore(
            int score
    ) {

        this.score =
                Math.max(
                        0,
                        Math.min(
                                100,
                                score
                        )
                );

        invalidate();
    }

    @Override
    protected void onDraw(
            Canvas canvas
    ) {

        super.onDraw(canvas);

        float padding =
                dpToPx(18);

        float size =
                Math.min(
                        getWidth(),
                        getHeight()
                );

        RectF oval =
                new RectF(
                        padding,
                        padding,
                        size - padding,
                        size - padding
                );

        canvas.drawArc(
                oval,
                -90,
                360,
                false,
                backgroundPaint
        );

        canvas.drawArc(
                oval,
                -90,
                360f * score / 100f,
                false,
                progressPaint
        );

        float centerX =
                size / 2f;

        float centerY =
                size / 2f;

        Paint.FontMetrics scoreMetrics =
                scorePaint.getFontMetrics();

        float scoreY =
                centerY
                        - (
                        scoreMetrics.ascent
                                + scoreMetrics.descent
                ) / 2f
                        - dpToPx(8);

        canvas.drawText(
                String.valueOf(score),
                centerX,
                scoreY,
                scorePaint
        );

        canvas.drawText(
                "Security Score",
                centerX,
                centerY + dpToPx(25),
                labelPaint
        );
    }

    private float dpToPx(
            float dp
    ) {

        return dp
                * getResources()
                .getDisplayMetrics()
                .density;
    }

    private float spToPx(
            float sp
    ) {

        return sp
                * getResources()
                .getDisplayMetrics()
                .scaledDensity;
    }
}