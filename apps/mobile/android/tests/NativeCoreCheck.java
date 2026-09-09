package com.vlightsoft.passkeyx;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicLong;

public final class NativeCoreCheck {
    private static int checks;
    static void check(boolean value) { checks++; if (!value) throw new AssertionError("Boundary check " + checks + " failed"); }
    public static void main(String[] args) {
        check(NativePolicy.official("https://passkey-x.com/app/android"));
        check(NativePolicy.official("https://passkey-x.com:443/login"));
        for (String url : new String[]{"http://passkey-x.com", "https://passkey-x.com:444", "https://passkey-x.com.attacker.test", "https://user@passkey-x.com", "https://passkey-x.com@attacker.test", "file:///tmp/vault", "javascript:alert(1)", "data:text/html,test", "intent://app", "https://passkey-x.com\\@attacker.test"}) check(!NativePolicy.official(url));
        for (String url : new String[]{"file:///tmp/vault", "content://private", "javascript:alert(1)", "intent://app", "https://user:password@example.test"}) check(!NativePolicy.external(url));
        check(NativePolicy.external("https://example.test"));
        check(NativePolicy.newPassword(new String[]{"new-password"}));
        check(!NativePolicy.newPassword(new String[]{"password"}));
        check(NativePolicy.password(null, 0x81)); check(NativePolicy.password(null, 0x12)); check(!NativePolicy.password(null, 0x21));
        check(NativePolicy.username(new String[]{"emailAddress"}, 0)); check(!NativePolicy.username(null, 1));
        check(NativePolicy.validSecret("", "synthetic-password")); check(!NativePolicy.validSecret("", "")); check(!NativePolicy.validSecret("a", "x".repeat(4097)));
        AtomicLong clock = new AtomicLong(1000); ArrayList<String> disposed = new ArrayList<>();
        ExpiringRequests<String> store = new ExpiringRequests<>(clock::get, disposed::add);
        String first = store.add("candidate-a"); check(store.get(first).equals("candidate-a"));
        clock.addAndGet(119999); check(store.get(first) != null); clock.incrementAndGet(); check(store.get(first) == null); check(disposed.size() == 1);
        String second = store.add("candidate-b"); store.remove(second); store.remove(second); check(store.get(second) == null); check(disposed.size() == 2);
        String rollback = store.add("rollback"); clock.decrementAndGet(); check(store.get(rollback) == null);
        String evicted = store.add("oldest"); for (int i=0;i<8;i++) store.add("pending-" + i); check(store.get(evicted) == null);
        check(store.get("unknown") == null); check(store.remaining("unknown") == 0);
        System.out.println("Passed " + checks + " native boundary checks.");
    }
}
