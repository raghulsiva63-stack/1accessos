package com.vlightsoft.passkeyx;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

/**
 * "Check link with Passkey-X" in Android's share sheet. Takes the first web link from the shared
 * text and opens Passkey-X, which checks it on the device. Nothing else from the sender is used.
 */
public class LinkCheckActivity extends Activity {
    @Override protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        Intent intent = getIntent();
        String text = null;
        if (intent != null && Intent.ACTION_SEND.equals(intent.getAction()) && "text/plain".equals(intent.getType())) {
            CharSequence value = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
            text = value == null ? null : value.toString();
        }
        String link = NativePolicy.firstWebLink(text);
        if (link != null) PendingLink.set(link);
        startActivity(new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP));
        finish();
    }
}
