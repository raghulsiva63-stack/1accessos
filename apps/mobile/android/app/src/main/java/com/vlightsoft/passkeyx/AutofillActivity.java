package com.vlightsoft.passkeyx;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.service.autofill.Dataset;
import android.view.autofill.AutofillManager;
import android.view.autofill.AutofillValue;
import android.widget.RemoteViews;
import android.widget.Toast;
import android.os.Handler;
import android.os.Looper;
import java.util.Arrays;
import androidx.webkit.JavaScriptReplyProxy;
import org.json.JSONObject;

public final class AutofillActivity extends MainActivity {
    private String operationId;
    private boolean confirmationOpen;
    private AlertDialog confirmation;
    private char[] fillPassword;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable expireConfirmation = () -> clearConfirmation();
    private void clearConfirmation() {
        handler.removeCallbacks(expireConfirmation);
        if (fillPassword != null) Arrays.fill(fillPassword, '\0');
        fillPassword = null; confirmationOpen = false;
        if (confirmation != null) { confirmation.dismiss(); confirmation = null; }
    }
    @Override protected boolean operationActivity() { return true; }
    @Override public void onCreate(Bundle saved) {
        operationId = getIntent().getStringExtra("operationId");
        super.onCreate(saved);
        setResult(RESULT_CANCELED);
        if (operationId == null || PendingAutofill.STORE.get(operationId) == null) { Toast.makeText(this, "Autofill request expired. Return to the other app and try again.", Toast.LENGTH_LONG).show(); finish(); }
    }
    @Override protected void handleNative(String action, JSONObject body, JavaScriptReplyProxy reply, String requestId) throws Exception {
        if (action.equals("status") || action.equals("enableAutofill") || action.equals("export")) { super.handleNative(action, body, reply, requestId); return; }
        PendingAutofill pending = PendingAutofill.STORE.get(operationId);
        if (pending == null) { reply(reply, requestId, null, "This request expired. Return to the other app and try again."); return; }
        if (action.equals("context")) {
            JSONObject context = new JSONObject().put("id", operationId).put("kind", pending.kind).put("packageName", pending.packageName).put("appLabel", pending.appLabel).put("expiresAt", System.currentTimeMillis() + PendingAutofill.STORE.remaining(operationId));
            if (pending.kind.equals("save")) context.put("username", pending.username()).put("password", pending.password());
            reply(reply, requestId, context, null); return;
        }
        if (!operationId.equals(body.optString("operationId"))) { reply(reply, requestId, null, "The autofill request changed. Try again."); return; }
        if (action.equals("cancel")) { reply(reply, requestId, true, null); PendingAutofill.STORE.remove(operationId); finish(); return; }
        if (action.equals("saved") && pending.kind.equals("save")) {
            PendingAutofill.STORE.remove(operationId); reply(reply, requestId, true, null);
            Toast.makeText(this, "Login saved in your encrypted vault", Toast.LENGTH_SHORT).show(); finish(); return;
        }
        if (action.equals("fill") && pending.kind.equals("fill") && !confirmationOpen) {
            String username = body.optString("username"), password = body.optString("password");
            if (!NativePolicy.validSecret(username, password)) throw new IllegalArgumentException();
            fillPassword = password.toCharArray();
            confirmationOpen = true;
            handler.postDelayed(expireConfirmation, PendingAutofill.STORE.remaining(operationId));
            confirmation = new AlertDialog.Builder(this).setTitle("Fill this login?")
                .setMessage("Send " + (username.isEmpty() ? "this password" : username) + " to " + pending.appLabel + "?\n\n" + pending.packageName + "\n\nOnly continue if you trust this app with this login.")
                .setPositiveButton("Fill login", (dialog, which) -> {
                    confirmationOpen = false;
                    if (!foreground || fillPassword == null || PendingAutofill.STORE.get(operationId) != pending) { clearConfirmation(); reply(reply, requestId, null, "The request expired."); return; }
                    RemoteViews presentation = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
                    presentation.setTextViewText(android.R.id.text1, username.isEmpty() ? "Passkey-X login" : username);
                    Dataset.Builder dataset = new Dataset.Builder(presentation).setValue(pending.passwordId, AutofillValue.forText(new String(fillPassword)));
                    if (pending.usernameId != null) dataset.setValue(pending.usernameId, AutofillValue.forText(username));
                    // Replace the selected locked dataset so Android fills immediately.
                    setResult(RESULT_OK, new Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset.build()));
                    PendingAutofill.STORE.remove(operationId); clearConfirmation(); reply(reply, requestId, true, null); finish();
                }).setNegativeButton("Cancel", (dialog, which) -> { clearConfirmation(); reply(reply, requestId, null, "Autofill cancelled."); })
                .setOnCancelListener(dialog -> { clearConfirmation(); reply(reply, requestId, null, "Autofill cancelled."); }).show();
            return;
        }
        reply(reply, requestId, null, "This action does not match the active request.");
    }
    @Override protected void onStop() { clearConfirmation(); super.onStop(); if (!isChangingConfigurations()) PendingAutofill.STORE.remove(operationId); }
    @Override protected void onDestroy() { clearConfirmation(); if (isFinishing()) PendingAutofill.STORE.remove(operationId); super.onDestroy(); }
}
