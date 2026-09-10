package com.vlightsoft.passkeyx;

import android.app.assist.AssistStructure;
import android.view.View;
import android.view.autofill.AutofillId;
import android.view.autofill.AutofillValue;
import java.util.ArrayList;
import java.util.List;

final class FormFields {
    final String packageName;
    final AssistStructure.ViewNode username;
    final AssistStructure.ViewNode password;
    final boolean newPassword;
    private FormFields(String pkg, AssistStructure.ViewNode user, AssistStructure.ViewNode pass) {
        packageName = pkg; username = user; password = pass; newPassword = NativePolicy.newPassword(pass.getAutofillHints());
    }
    AutofillId[] ids() { return username == null ? new AutofillId[]{password.getAutofillId()} : new AutofillId[]{username.getAutofillId(), password.getAutofillId()}; }
    static String text(AssistStructure.ViewNode node) {
        AutofillValue value = node == null ? null : node.getAutofillValue();
        return value != null && value.isText() ? value.getTextValue().toString() : "";
    }
    static FormFields parse(AssistStructure structure, String ownPackage) {
        if (structure == null || structure.getActivityComponent() == null) return null;
        String pkg = structure.getActivityComponent().getPackageName();
        if (pkg.equals(ownPackage) || !pkg.matches("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")) return null;
        List<AssistStructure.ViewNode> nodes = new ArrayList<>();
        int[] budget = {2000};
        for (int w = 0; w < Math.min(structure.getWindowNodeCount(), 8); w++) collect(structure.getWindowNodeAt(w).getRootViewNode(), false, 0, budget, nodes);
        List<AssistStructure.ViewNode> passwords = new ArrayList<>();
        List<AssistStructure.ViewNode> users = new ArrayList<>();
        for (var node : nodes) {
            if (NativePolicy.password(node.getAutofillHints(), node.getInputType())) passwords.add(node);
            else if (NativePolicy.username(node.getAutofillHints(), node.getInputType())) users.add(node);
        }
        // Ambiguous forms fail closed; prefer the explicitly declared new password for saving.
        List<AssistStructure.ViewNode> newPasswords = new ArrayList<>();
        for (var node : passwords) if (NativePolicy.newPassword(node.getAutofillHints())) newPasswords.add(node);
        var candidates = newPasswords.isEmpty() ? passwords : newPasswords;
        if (candidates.size() != 1 || users.size() > 1) return null;
        return new FormFields(pkg, users.isEmpty() ? null : users.get(0), candidates.get(0));
    }
    private static void collect(AssistStructure.ViewNode node, boolean web, int depth, int[] budget, List<AssistStructure.ViewNode> nodes) {
        if (node == null || depth > 40 || --budget[0] < 0) return;
        if (node.getVisibility() != View.VISIBLE) return;
        // Native apps only. Unverified web domains and embedded web forms are never treated as app credentials.
        web |= node.getWebDomain() != null || node.getHtmlInfo() != null || "android.webkit.WebView".equals(node.getClassName());
        if (!web && node.getVisibility() == View.VISIBLE && node.getAutofillId() != null && node.getAutofillType() == View.AUTOFILL_TYPE_TEXT) nodes.add(node);
        for (int i = 0; i < node.getChildCount() && budget[0] > 0; i++) collect(node.getChildAt(i), web, depth + 1, budget, nodes);
    }
}
