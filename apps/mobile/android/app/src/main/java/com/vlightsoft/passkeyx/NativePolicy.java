package com.vlightsoft.passkeyx;

import java.net.URI;
import java.util.Locale;

/** Pure boundary decisions, shared with JVM tests. */
final class NativePolicy {
    static final String VAULT = "https://passkey-x.com/app/android";
    static boolean official(String value) {
        try {
            URI uri = new URI(value);
            return "https".equals(uri.getScheme()) && "passkey-x.com".equals(uri.getHost())
                && (uri.getPort() == -1 || uri.getPort() == 443) && uri.getUserInfo() == null;
        } catch (Exception ignored) { return false; }
    }
    static boolean external(String value) {
        try {
            URI uri = new URI(value);
            return ("https".equals(uri.getScheme()) || "http".equals(uri.getScheme())) && uri.getHost() != null && uri.getUserInfo() == null;
        } catch (Exception ignored) { return false; }
    }
    static boolean validSecret(String username, String password) {
        return username != null && username.length() <= 1024 && password != null && !password.isEmpty() && password.length() <= 4096;
    }
    static boolean newPassword(String[] hints) {
        if (hints == null) return false;
        for (String hint : hints) if (hint != null && hint.toLowerCase(Locale.ROOT).replace("-", "").equals("newpassword")) return true;
        return false;
    }
    static boolean password(String[] hints, int inputType) {
        if (hints != null) for (String hint : hints) if (hint != null) {
            String normalized = hint.toLowerCase(Locale.ROOT).replace("-", "");
            if (normalized.contains("otp") || normalized.equals("onetimecode") || normalized.equals("onetimepassword")) return false;
        }
        if (hints != null) for (String hint : hints) if (hint != null) {
            String normalized = hint.toLowerCase(Locale.ROOT).replace("-", "");
            if (normalized.equals("password") || normalized.equals("currentpassword") || normalized.equals("newpassword")) return true;
        }
        int variation = inputType & 0xfff;
        return variation == 0x81 || variation == 0x91 || variation == 0xe1 || variation == 0x12;
    }
    static boolean username(String[] hints, int inputType) {
        if (hints != null) for (String hint : hints) if (hint != null && (hint.equalsIgnoreCase("username") || hint.equalsIgnoreCase("emailAddress") || hint.equalsIgnoreCase("email") || hint.equalsIgnoreCase("newUsername"))) return true;
        return (inputType & 0xfff) == 0x21;
    }
}
