package com.safekey.app.security.crypto;

import android.os.SystemClock;
import android.util.Log;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(AndroidJUnit4.class)
public class Argon2idBenchmarkInstrumentedTest {

    private static final String LOG_TAG =
            "SafeKeyArgon2Benchmark";

    private static final int MEASURED_RUNS = 3;

    @Test
    public void deriveKey_onAndroid_reportsDuration()
            throws Exception {

        Argon2idMasterKeyDeriver deriver =
                new Argon2idMasterKeyDeriver();

        char[] masterPassword =
                "benchmark-only-master-password"
                        .toCharArray();

        byte[] salt =
                deriver.generateSalt();

        byte[] warmupKey = null;

        try {
            warmupKey =
                    deriver.deriveKey(
                            masterPassword,
                            salt
                    );

            assertEquals(
                    Argon2idMasterKeyDeriver
                            .DERIVED_KEY_LENGTH_BYTES,
                    warmupKey.length
            );

        } finally {
            if (warmupKey != null) {
                Arrays.fill(
                        warmupKey,
                        (byte) 0
                );
            }
        }

        long minimumNanoseconds =
                Long.MAX_VALUE;

        long maximumNanoseconds = 0;
        long totalNanoseconds = 0;

        try {
            for (
                    int run = 0;
                    run < MEASURED_RUNS;
                    run++
            ) {
                byte[] derivedKey = null;

                long startNanoseconds =
                        SystemClock.elapsedRealtimeNanos();

                try {
                    derivedKey =
                            deriver.deriveKey(
                                    masterPassword,
                                    salt
                            );

                    long durationNanoseconds =
                            SystemClock.elapsedRealtimeNanos()
                                    - startNanoseconds;

                    assertEquals(
                            Argon2idMasterKeyDeriver
                                    .DERIVED_KEY_LENGTH_BYTES,
                            derivedKey.length
                    );

                    assertTrue(
                            durationNanoseconds > 0
                    );

                    minimumNanoseconds =
                            Math.min(
                                    minimumNanoseconds,
                                    durationNanoseconds
                            );

                    maximumNanoseconds =
                            Math.max(
                                    maximumNanoseconds,
                                    durationNanoseconds
                            );

                    totalNanoseconds +=
                            durationNanoseconds;

                } finally {
                    if (derivedKey != null) {
                        Arrays.fill(
                                derivedKey,
                                (byte) 0
                        );
                    }
                }
            }

            double minimumMilliseconds =
                    minimumNanoseconds
                            / 1_000_000.0;

            double averageMilliseconds =
                    (
                            totalNanoseconds
                                    / (double) MEASURED_RUNS
                    )
                            / 1_000_000.0;

            double maximumMilliseconds =
                    maximumNanoseconds
                            / 1_000_000.0;

            Log.i(
                    LOG_TAG,
                    "Argon2id benchmark: memory="
                            + Argon2idMasterKeyDeriver.MEMORY_KIB
                            + " KiB, iterations="
                            + Argon2idMasterKeyDeriver.ITERATIONS
                            + ", parallelism="
                            + Argon2idMasterKeyDeriver.PARALLELISM
                            + ", minimum="
                            + minimumMilliseconds
                            + " ms, average="
                            + averageMilliseconds
                            + " ms, maximum="
                            + maximumMilliseconds
                            + " ms"
            );

        } finally {
            Arrays.fill(
                    masterPassword,
                    '\0'
            );

            Arrays.fill(
                    salt,
                    (byte) 0
            );
        }
    }
}
