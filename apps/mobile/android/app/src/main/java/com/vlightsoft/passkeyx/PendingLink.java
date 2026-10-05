package com.vlightsoft.passkeyx;

import android.os.SystemClock;

/** A link shared to Passkey-X for checking. Kept in memory for two minutes, handed out once. */
final class PendingLink {
    private static String link;
    private static long at;
    static synchronized void set(String value) { link = value; at = SystemClock.elapsedRealtime(); }
    static synchronized String take() {
        String value = link != null && SystemClock.elapsedRealtime() - at <= 120_000 ? link : null;
        link = null;
        return value;
    }
    static synchronized boolean waiting() { return link != null && SystemClock.elapsedRealtime() - at <= 120_000; }
}
