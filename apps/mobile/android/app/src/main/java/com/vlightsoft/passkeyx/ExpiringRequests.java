package com.vlightsoft.passkeyx;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.function.LongSupplier;
import java.util.function.Consumer;

/** Never serialized. Process death, expiry and explicit removal discard pending secrets. */
final class ExpiringRequests<T> {
    static final long TTL = 120_000;
    private record Entry<T>(T value, long created) {}
    private final Map<String, Entry<T>> entries = new LinkedHashMap<>();
    private final LongSupplier clock;
    private final Consumer<T> dispose;
    ExpiringRequests(LongSupplier clock, Consumer<T> dispose) { this.clock = clock; this.dispose = dispose; }
    synchronized String add(T value) {
        purge();
        while (entries.size() >= 8) remove(entries.keySet().iterator().next());
        String id = UUID.randomUUID().toString(); entries.put(id, new Entry<>(value, clock.getAsLong())); return id;
    }
    synchronized T get(String id) { purge(); Entry<T> entry = entries.get(id); return entry == null ? null : entry.value(); }
    synchronized long remaining(String id) { purge(); Entry<T> entry = entries.get(id); return entry == null ? 0 : TTL - (clock.getAsLong() - entry.created()); }
    synchronized void remove(String id) { Entry<T> entry = entries.remove(id); if (entry != null) dispose.accept(entry.value()); }
    synchronized void purge() {
        long now = clock.getAsLong();
        var iterator = entries.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next().getValue();
            if (now - entry.created() >= TTL || now < entry.created()) { dispose.accept(entry.value()); iterator.remove(); }
        }
    }
}
