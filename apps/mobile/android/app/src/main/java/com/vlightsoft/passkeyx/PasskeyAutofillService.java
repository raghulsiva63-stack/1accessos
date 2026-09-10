package com.vlightsoft.passkeyx;

import android.app.PendingIntent;
import android.content.Intent;
import android.os.CancellationSignal;
import android.service.autofill.*;
import android.widget.RemoteViews;
import java.util.List;

public final class PasskeyAutofillService extends AutofillService {
    static SaveInfo saveInfo(FormFields fields) {
        SaveInfo.Builder builder = new SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD, new android.view.autofill.AutofillId[]{fields.password.getAutofillId()});
        if (fields.username != null) builder.setOptionalIds(new android.view.autofill.AutofillId[]{fields.username.getAutofillId()});
        builder.setDescription("Review in Passkey-X, then choose an encrypted workspace to save.");
        return builder.build();
    }
    private FormFields fields(List<FillContext> contexts) { return contexts.isEmpty() ? null : FormFields.parse(contexts.get(contexts.size() - 1).getStructure(), getPackageName()); }
    private String label(String pkg) {
        try { return getPackageManager().getApplicationLabel(getPackageManager().getApplicationInfo(pkg, 0)).toString(); }
        catch (Exception ignored) { return pkg; }
    }
    private PendingIntent intent(String id) {
        Intent intent = new Intent(this, AutofillActivity.class).setAction("com.vlightsoft.passkeyx.AUTOFILL." + id).putExtra("operationId", id);
        // No mutable extras or secrets. Field IDs live in the service's bounded memory store.
        return PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_ONE_SHOT);
    }
    @Override public void onFillRequest(FillRequest request, CancellationSignal cancellation, FillCallback callback) {
        FormFields fields;
        try { fields = fields(request.getFillContexts()); } catch (RuntimeException ignored) { callback.onSuccess(null); return; }
        if (fields == null || cancellation.isCanceled()) { callback.onSuccess(null); return; }
        FillResponse.Builder response = new FillResponse.Builder().setSaveInfo(saveInfo(fields));
        if (!fields.newPassword) {
            String id = PendingAutofill.put(new PendingAutofill("fill", fields, label(fields.packageName)));
            cancellation.setOnCancelListener(() -> PendingAutofill.STORE.remove(id));
            RemoteViews presentation = new RemoteViews(getPackageName(), android.R.layout.simple_list_item_1);
            presentation.setTextViewText(android.R.id.text1, "Unlock Passkey-X to choose a login");
            Dataset.Builder locked = new Dataset.Builder(presentation)
                .setValue(fields.password.getAutofillId(), null)
                .setAuthentication(intent(id).getIntentSender());
            if (fields.username != null) locked.setValue(fields.username.getAutofillId(), null);
            response.addDataset(locked.build());
        }
        callback.onSuccess(response.build());
    }
    @Override public void onSaveRequest(SaveRequest request, SaveCallback callback) {
        FormFields fields;
        try { fields = fields(request.getFillContexts()); } catch (RuntimeException ignored) { callback.onFailure("Unsupported login form"); return; }
        if (fields == null || !NativePolicy.validSecret(FormFields.text(fields.username), FormFields.text(fields.password))) { callback.onFailure("Unsupported login form"); return; }
        String id = PendingAutofill.put(new PendingAutofill("save", fields, label(fields.packageName)));
        // Android's user-approved save flow continues into vault login/unlock and explicit review.
        callback.onSuccess(intent(id).getIntentSender());
    }
}
