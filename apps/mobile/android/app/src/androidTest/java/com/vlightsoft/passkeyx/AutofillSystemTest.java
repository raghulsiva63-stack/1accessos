package com.vlightsoft.passkeyx;

import android.app.Instrumentation;
import android.content.Intent;
import android.content.ComponentName;
import android.os.ParcelFileDescriptor;
import android.view.WindowManager;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import androidx.test.uiautomator.*;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class AutofillSystemTest {
    final Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
    final UiDevice device = UiDevice.getInstance(instrumentation);
    private void shell(String command) throws Exception {
        try (ParcelFileDescriptor descriptor = instrumentation.getUiAutomation().executeShellCommand(command); var input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor)) { while (input.read() != -1) {} }
    }
    private UiObject2 waitFor(BySelector selector) {
        UiObject2 object = device.wait(Until.findObject(selector), 15_000);
        assertNotNull("Expected Android UI: " + selector, object); return object;
    }
    private void launchFixture() {
        Intent intent = new Intent().setComponent(new ComponentName("com.vlightsoft.passkeyx.fixture", "com.vlightsoft.passkeyx.fixture.FixtureActivity")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        instrumentation.getTargetContext().startActivity(intent);
    }
    @Test public void androidFillAndSaveRequireAnExplicitHandoff() throws Exception {
        String provider = instrumentation.getTargetContext().getPackageName() + "/com.vlightsoft.passkeyx.PasskeyAutofillService";
        shell("settings put secure autofill_service " + provider);
        try {
            launchFixture();
            waitFor(By.desc("Fixture username")).click();
            var monitor = instrumentation.addMonitor(AutofillActivity.class.getName(), null, false);
            waitFor(By.text("Unlock Passkey-X to choose a login")).click();
            AutofillActivity activity = (AutofillActivity) instrumentation.waitForMonitorWithTimeout(monitor, 15_000);
            assertNotNull("Android must open the provider's private activity", activity);
            assertNotEquals(0, activity.getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE);
            String id = activity.getIntent().getStringExtra("operationId");
            PendingAutofill request = PendingAutofill.STORE.get(id);
            assertNotNull(request); assertEquals("fill", request.kind); assertEquals("com.vlightsoft.passkeyx.fixture", request.packageName); assertEquals("", request.password());
            // Substitute only the post-unlock selection here: no real account or vault is involved.
            instrumentation.runOnMainSync(() -> {
                try { activity.handleNative("fill", new JSONObject().put("operationId", id).put("username", "uat-user").put("password", "synthetic-password-42"), null, "test-reply"); }
                catch (Exception error) { throw new AssertionError(error); }
            });
            waitFor(By.text("Fill this login?"));
            waitFor(By.res("android", "button1")).click();
            waitFor(By.text("Verify test fill")).click();
            waitFor(By.text("Autofill received correctly"));
            assertNull("The filled request cannot be replayed", PendingAutofill.STORE.get(id));
            instrumentation.removeMonitor(monitor);

            // A changed login should invoke Android's Save UI, then the provider's review activity.
            waitFor(By.desc("Fixture password")).setText("changed-synthetic-password-43");
            var saveMonitor = instrumentation.addMonitor(AutofillActivity.class.getName(), null, false);
            waitFor(By.text("Submit test login")).click();
            waitFor(By.res("android", "autofill_save_yes")).click();
            AutofillActivity saving = (AutofillActivity) instrumentation.waitForMonitorWithTimeout(saveMonitor, 15_000);
            assertNotNull("Save must open vault review", saving);
            String saveId = saving.getIntent().getStringExtra("operationId");
            PendingAutofill candidate = PendingAutofill.STORE.get(saveId);
            assertNotNull(candidate); assertEquals("save", candidate.kind); assertEquals("uat-user", candidate.username()); assertEquals("changed-synthetic-password-43", candidate.password());
            assertTrue(PendingAutofill.STORE.remaining(saveId) <= 120_000);
            device.pressBack(); device.waitForIdle();
            assertNull("Cancelling discards the pending login", PendingAutofill.STORE.get(saveId));
            instrumentation.removeMonitor(saveMonitor);
        } finally { shell("settings delete secure autofill_service"); }
    }
}
