package vn.secureproxy.security;

import vn.secureproxy.PolicyService;
import vn.secureproxy.policy.PolicyConfig;

import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class SecurityCheck {

    private static int passed;
    private static int failed;

    private static void check(String name, boolean actual, boolean expected) {
        if (actual == expected) {
            passed++;
            System.out.println("PASS " + name);
        } else {
            failed++;
            System.out.println("FAIL " + name + " expected=" + expected + " actual=" + actual);
        }
    }

    public static void main(String[] args) throws Exception {
        IpAccessControl access = new IpAccessControl(IpAccessControl.DEFAULT_CIDRS);
        check("allow loopback", access.isAllowed(InetAddress.getByName("127.0.0.1")), true);
        check("allow private IPv4", access.isAllowed(InetAddress.getByName("10.12.0.8")), true);
        check("allow Docker private IPv4", access.isAllowed(InetAddress.getByName("172.19.0.1")), true);
        check("allow private IPv6", access.isAllowed(InetAddress.getByName("fd12::5")), true);
        check("deny public IPv4", access.isAllowed(InetAddress.getByName("8.8.8.8")), false);
        check("deny public IPv6", access.isAllowed(InetAddress.getByName("2001:4860:4860::8888")), false);
        check("allow IPv4-mapped loopback", access.isAllowed(InetAddress.getByName("::ffff:127.0.0.1")), true);

        IpRateLimiter limiter = new IpRateLimiter(60, 2);
        InetAddress first = InetAddress.getByName("192.168.1.10");
        InetAddress second = InetAddress.getByName("192.168.1.11");
        check("allow within burst one", limiter.allow(first), true);
        check("allow within burst two", limiter.allow(first), true);
        check("deny beyond burst", limiter.allow(first), false);
        check("rate limit isolated per IP", limiter.allow(second), true);

        PolicyService policy = new PolicyService(
                new PolicyConfig("BLOCKLIST", "UTC", List.of("phish.example"), List.of()),
                List.of(),
                List.of("phish.example"),
                List.of("tracker.example")
        );
        check("phishing feed takes precedence over allowlist",
                !policy.danhGia("phish.example").allowed()
                        && policy.danhGia("phish.example").reason().equals("phishing-feed"), true);
        check("phishing feed matches subdomains",
                !policy.danhGia("login.phish.example").allowed(), true);
        check("ads/tracker feed blocks matching domains",
                !policy.danhGia("cdn.tracker.example").allowed()
                        && policy.danhGia("cdn.tracker.example").reason().equals("ads-tracker-feed"), true);
        check("unlisted domain remains allowed",
                policy.danhGia("safe.example").allowed(), true);

        if (args.length > 0) {
            Path dataDirectory = Path.of(args[0]);
            List<String> phishingDomains = Files.readAllLines(
                    dataDirectory.resolve("phishing-domains.txt"));
            List<String> adTrackerDomains = Files.readAllLines(
                    dataDirectory.resolve("ads-trackers.txt"));
            check("phishing feed cache populated", phishingDomains.size() > 0, true);
            check("ads/tracker feed cache populated", adTrackerDomains.size() >= 100, true);
            PolicyService feedPolicy = new PolicyService(
                    new PolicyConfig("BLOCKLIST", "UTC", List.of(), List.of()),
                    List.of(),
                    phishingDomains,
                    adTrackerDomains
            );
            check("cached phishing domain is blocked",
                    !feedPolicy.danhGia(phishingDomains.get(0)).allowed(), true);
            check("cached tracker domain is blocked",
                    !feedPolicy.danhGia(adTrackerDomains.get(0)).allowed(), true);
        }

        System.out.println("PASS: " + passed + "  FAIL: " + failed);
        if (failed > 0) {
            System.exit(1);
        }
    }
}
