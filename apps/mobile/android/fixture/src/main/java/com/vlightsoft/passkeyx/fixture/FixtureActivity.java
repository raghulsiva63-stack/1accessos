package com.vlightsoft.passkeyx.fixture;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.autofill.AutofillManager;
import android.widget.*;

/** Isolated, offline test app. Never packaged into the password manager APK. */
public final class FixtureActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this); layout.setOrientation(LinearLayout.VERTICAL); layout.setPadding(24, 100, 24, 24);
        EditText username = new EditText(this); username.setId(View.generateViewId()); username.setHint("Fixture username"); username.setContentDescription("Fixture username"); username.setAutofillHints(View.AUTOFILL_HINT_USERNAME); username.setInputType(InputType.TYPE_CLASS_TEXT);
        EditText password = new EditText(this); password.setId(View.generateViewId()); password.setHint("Fixture password"); password.setContentDescription("Fixture password"); password.setAutofillHints(View.AUTOFILL_HINT_PASSWORD); password.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        TextView status = new TextView(this);
        Button verify = new Button(this); verify.setText("Verify test fill"); verify.setAllCaps(false); verify.setOnClickListener(view -> status.setText(username.getText().toString().equals("uat-user") && password.getText().toString().equals("synthetic-password-42") ? "Autofill received correctly" : "No matching test fill"));
        Button submit = new Button(this); submit.setText("Submit test login"); submit.setAllCaps(false); submit.setOnClickListener(view -> { getSystemService(AutofillManager.class).commit(); status.setText("Test login submitted"); });
        layout.addView(username); layout.addView(password); layout.addView(verify); layout.addView(submit); layout.addView(status); setContentView(layout);
    }
}
