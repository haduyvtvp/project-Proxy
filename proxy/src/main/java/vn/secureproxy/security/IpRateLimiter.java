package vn.secureproxy.security;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public final class IpRateLimiter {

    private static final int MAX_TRACKED_ADDRESSES = 100_000;

    private static final class Bucket {
        private double tokens;
        private long updatedAtNanos;

        private Bucket(double capacity, long now) {
            this.tokens = capacity;
            this.updatedAtNanos = now;
        }

        private boolean take(double capacity, double tokensPerNano, long now) {
            long elapsed = Math.max(0, now - updatedAtNanos);
            tokens = Math.min(capacity, tokens + elapsed * tokensPerNano);
            updatedAtNanos = now;
            if (tokens < 1) {
                return false;
            }
            tokens -= 1;
            return true;
        }
    }

    private final double capacity;
    private final double tokensPerNano;
    private final ConcurrentHashMap<String, Bucket> buckets = new ConcurrentHashMap<>();

    public IpRateLimiter(int requestsPerMinute, int burst) {
        if (requestsPerMinute < 1 || burst < 1) {
            throw new IllegalArgumentException("Rate and burst must be positive");
        }
        this.capacity = burst;
        this.tokensPerNano = requestsPerMinute / 60_000_000_000.0;
    }

    public boolean allow(InetAddress address) {
        long now = System.nanoTime();
        String key = address.getHostAddress();
        AtomicBoolean allowed = new AtomicBoolean();
        buckets.compute(key, (ip, bucket) -> {
            if (bucket == null) {
                if (buckets.size() >= MAX_TRACKED_ADDRESSES) {
                    return null;
                }
                bucket = new Bucket(capacity, now);
            }
            allowed.set(bucket.take(capacity, tokensPerNano, now));
            return bucket;
        });
        return allowed.get();
    }
}
