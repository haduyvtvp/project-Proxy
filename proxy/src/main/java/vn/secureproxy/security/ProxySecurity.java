package vn.secureproxy.security;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;

public final class ProxySecurity {

    private final IpAccessControl accessControl;
    private final IpRateLimiter rateLimiter;

    public ProxySecurity(IpAccessControl accessControl, IpRateLimiter rateLimiter) {
        this.accessControl = accessControl;
        this.rateLimiter = rateLimiter;
    }

    public static ProxySecurity fromEnvironment() {
        String cidrs = environment("PROXY_ALLOWED_CIDRS", IpAccessControl.DEFAULT_CIDRS);
        int requestsPerMinute = integerEnvironment("PROXY_RATE_LIMIT_PER_MINUTE", 120);
        int burst = integerEnvironment("PROXY_RATE_LIMIT_BURST", 30);
        return new ProxySecurity(
                new IpAccessControl(cidrs),
                new IpRateLimiter(requestsPerMinute, burst)
        );
    }

    public boolean isTrusted(SocketAddress remoteAddress) {
        return accessControl.isAllowed(address(remoteAddress));
    }

    public boolean allowRequest(SocketAddress remoteAddress) {
        InetAddress ip = address(remoteAddress);
        return ip != null && rateLimiter.allow(ip);
    }

    private static InetAddress address(SocketAddress remoteAddress) {
        if (remoteAddress instanceof InetSocketAddress socketAddress) {
            return socketAddress.getAddress();
        }
        return null;
    }

    private static String environment(String name, String fallback) {
        String value = System.getenv(name);
        return value == null ? fallback : value;
    }

    private static int integerEnvironment(String name, int fallback) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer", e);
        }
    }
}
