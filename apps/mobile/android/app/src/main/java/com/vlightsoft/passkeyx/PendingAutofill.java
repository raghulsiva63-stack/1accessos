package com.vlightsoft.passkeyx;

import android.os.Handler;
import android.os.Looper;
import android.os.SystemClock;
import android.view.autofill.AutofillId;
import java.util.Arrays;

final class PendingAutofill {
    static final ExpiringRequests<PendingAutofill> STORE = new ExpiringRequests<>(SystemClock::elapsedRealtime, PendingAutofill::clear);
    final String kind, packageName, appLabel;
    final AutofillId usernameId, passwordId;
    private char[] username, password;
    PendingAutofill(String kind, FormFields fields, String label) {
        this.kind = kind; packageName = fields.packageName; appLabel = label.substring(0, Math.min(label.length(), 120));
        usernameId = fields.username == null ? null : fields.username.getAutofillId(); passwordId = fields.password.getAutofillId();
        // Fill requests keep only field identifiers. Do not retain text a user has already typed.
        username = (kind.equals("save") ? FormFields.text(fields.username) : "").toCharArray();
        password = (kind.equals("save") ? FormFields.text(fields.password) : "").toCharArray();
    }
    String username() { return new String(username); }
    String password() { return new String(password); }
    void clear() { Arrays.fill(username, '\0'); Arrays.fill(password, '\0'); username = new char[0]; password = new char[0]; }
    static String put(PendingAutofill pending) {
        String id = STORE.add(pending);
        new Handler(Looper.getMainLooper()).postDelayed(() -> STORE.remove(id), ExpiringRequests.TTL);
        return id;
    }
}
