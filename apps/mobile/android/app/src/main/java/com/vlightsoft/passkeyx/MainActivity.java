package com.vlightsoft.passkeyx;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.util.Base64;
import android.view.View;
import android.view.WindowManager;
import android.view.autofill.AutofillManager;
import android.webkit.*;
import android.widget.*;
import androidx.webkit.WebViewCompat;
import androidx.webkit.WebViewFeature;
import androidx.webkit.JavaScriptReplyProxy;
import org.json.JSONObject;
import java.util.Arrays;
import java.util.Set;

public class MainActivity extends Activity {
    protected WebView web;
    private TextView status;
    private ValueCallback<Uri[]> fileCallback;
    private byte[] exportBytes;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable expireExport = () -> clearExport();
    protected boolean foreground;
    protected boolean operationActivity() { return false; }

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setBackgroundColor(0xfff3f6fc);
        root.setOnApplyWindowInsetsListener((view, insets) -> { view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(), insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom()); return insets; });
        LinearLayout bar = new LinearLayout(this);
        TextView title = new TextView(this); title.setText("Passkey-X · Android"); title.setTextSize(16); title.setPadding(20, 14, 0, 14);
        bar.addView(title, new LinearLayout.LayoutParams(0, -2, 1));
        Button menu = new Button(this); menu.setText("App menu"); bar.addView(menu); root.addView(bar);
        menu.setOnClickListener(view -> new AlertDialog.Builder(this).setTitle("Passkey-X Android").setItems(new String[]{"Autofill settings", "Lock vault", "Reload", "Open web vault in browser", "Cancel / close"}, (dialog, which) -> {
            if (which == 0) enableAutofill();
            if (which == 1) lockVault();
            if (which == 2) { lockVault(); web.reload(); }
            if (which == 3) { lockVault(); openExternal("https://passkey-x.com/login"); }
            if (which == 4) finish();
        }).show());
        status = new TextView(this); status.setPadding(20, 6, 20, 10); status.setText("Connecting to your vault…"); root.addView(status);
        web = new WebView(this); root.addView(web, new LinearLayout.LayoutParams(-1, 0, 1)); setContentView(root);
        WebView.setWebContentsDebuggingEnabled(false);
        web.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        WebSettings settings = web.getSettings();
        settings.setJavaScriptEnabled(true); settings.setDomStorageEnabled(true);
        settings.setAllowFileAccess(false); settings.setAllowContentAccess(true);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setSafeBrowsingEnabled(true); settings.setSaveFormData(false);
        settings.setJavaScriptCanOpenWindowsAutomatically(false); settings.setSupportMultipleWindows(false);
        CookieManager.getInstance().setAcceptThirdPartyCookies(web, false);
        web.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                if (!request.isForMainFrame()) return false;
                String url = request.getUrl().toString();
                if (NativePolicy.official(url)) return false;
                if (request.hasGesture() && NativePolicy.external(url)) { lockVault(); openExternal(url); }
                return true;
            }
            @Override public void onPageFinished(WebView view, String url) { status.setText(NativePolicy.official(url) ? "Online vault · locks when you leave" : "Open the secure vault to continue"); }
            @Override public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) { if (request.isForMainFrame()) status.setText("Unable to connect. Check your connection, then choose Reload in App menu."); }
            @Override public void onReceivedSslError(WebView view, SslErrorHandler handler, android.net.http.SslError error) { handler.cancel(); status.setText("Secure connection failed. Try again later."); }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView view, ValueCallback<Uri[]> callback, FileChooserParams params) {
                if (!foreground || !NativePolicy.official(view.getUrl())) return false;
                if (fileCallback != null) fileCallback.onReceiveValue(null);
                fileCallback = callback;
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
                intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, params.getMode() == FileChooserParams.MODE_OPEN_MULTIPLE);
                try { startActivityForResult(intent, 91); } catch (Exception ignored) { fileCallback.onReceiveValue(null); fileCallback = null; }
                return true;
            }
            @Override public void onPermissionRequest(PermissionRequest request) { request.deny(); }
        });
        web.setDownloadListener((url, userAgent, disposition, mimeType, length) -> {
            if (NativePolicy.official(url)) openExternal(url);
            else status.setText("Use the web vault in your browser for this download.");
        });
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(web, "PasskeyXNative", Set.of("https://passkey-x.com"), (view, message, origin, mainFrame, reply) -> {
                if (!mainFrame || !foreground || !NativePolicy.official(origin.toString()) || !NativePolicy.official(view.getUrl())) return;
                String raw = message.getData();
                if (raw == null || raw.length() > 36_000_000) return;
                String requestId = "";
                try {
                    JSONObject body = new JSONObject(raw); requestId = body.optString("requestId");
                    if (!requestId.matches("[a-f0-9-]{36}")) return;
                    handleNative(body.optString("action"), body, reply, requestId);
                } catch (Exception ignored) { reply(reply, requestId, null, "That operation could not complete. Try again."); }
            });
        } else status.setText("Update Android System WebView to enable autofill integration.");
        // Ignore launcher Intent data/extras. No external caller can redirect the vault or inject a request.
        web.loadUrl(NativePolicy.VAULT);
    }

    protected void handleNative(String action, JSONObject body, JavaScriptReplyProxy reply, String requestId) throws Exception {
        switch (action) {
            case "status": reply(reply, requestId, new JSONObject().put("enabled", getSystemService(AutofillManager.class).hasEnabledAutofillServices()), null); break;
            case "enableAutofill": reply(reply, requestId, true, null); enableAutofill(); break;
            case "context": reply(reply, requestId, JSONObject.NULL, null); break;
            case "export":
                if (exportBytes != null) throw new IllegalStateException("Export in progress");
                String encoded = body.optString("base64"), filename = body.optString("filename");
                if (encoded.length() > 35_000_000 || filename.isEmpty() || filename.length() > 160 || filename.contains("/") || filename.contains("\\") || filename.contains("\0")) throw new IllegalArgumentException();
                byte[] decoded = Base64.decode(encoded, Base64.NO_WRAP);
                if (decoded.length > 25_000_000) { Arrays.fill(decoded, (byte)0); throw new IllegalArgumentException(); }
                exportBytes = decoded; handler.postDelayed(expireExport, 120_000);
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("application/octet-stream").putExtra(Intent.EXTRA_TITLE, filename);
                startActivityForResult(intent, 92); reply(reply, requestId, true, null); break;
            default: reply(reply, requestId, null, "No active autofill request. Return to the other app and try again.");
        }
    }
    protected final void reply(JavaScriptReplyProxy proxy, String requestId, Object data, String error) {
        try { JSONObject response = new JSONObject().put("requestId", requestId); if (error != null) response.put("error", error); else response.put("data", data == null ? JSONObject.NULL : data); proxy.postMessage(response.toString()); } catch (Exception ignored) { /* Navigated or closed. Never log credential payloads. */ }
    }
    protected void lockVault() { if (web != null) web.evaluateJavascript("window.dispatchEvent(new Event('passkey-x:lock'));", null); }
    private void enableAutofill() {
        lockVault();
        try { startActivity(new Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:" + getPackageName()))); }
        catch (Exception ignored) { status.setText("Open Android Settings and search for Autofill service, then select Passkey-X."); }
    }
    private void openExternal(String url) { if (NativePolicy.external(url)) try { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))); } catch (Exception ignored) { status.setText("No browser is available for this link."); } }
    @Override protected void onResume() { super.onResume(); foreground = true; if (web != null) web.onResume(); }
    @Override protected void onPause() { foreground = false; lockVault(); if (web != null) web.onPause(); super.onPause(); }
    @Override public void onBackPressed() { lockVault(); if (operationActivity()) finish(); else if (web.canGoBack()) web.goBack(); else super.onBackPressed(); }
    private void clearExport() { handler.removeCallbacks(expireExport); if (exportBytes != null) Arrays.fill(exportBytes, (byte)0); exportBytes = null; }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 91 && fileCallback != null) { fileCallback.onReceiveValue(WebChromeClient.FileChooserParams.parseResult(result, data)); fileCallback = null; }
        if (request == 92) {
            if (result == RESULT_OK && data != null && data.getData() != null && exportBytes != null) {
                try (var output = getContentResolver().openOutputStream(data.getData(), "w")) { if (output == null) throw new IllegalStateException(); output.write(exportBytes); status.setText("File saved to your selected location."); }
                catch (Exception ignored) { status.setText("The file could not be saved. Try exporting again."); }
            } else status.setText("Export cancelled or expired. No file was saved.");
            clearExport();
        }
    }
    @Override protected void onDestroy() { clearExport(); if (fileCallback != null) fileCallback.onReceiveValue(null); if (web != null) { lockVault(); web.destroy(); web = null; } super.onDestroy(); }
}
