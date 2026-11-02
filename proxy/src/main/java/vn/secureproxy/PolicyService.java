package vn.secureproxy;

import vn.secureproxy.policy.Decision;
import vn.secureproxy.policy.DomainMatcher;
import vn.secureproxy.policy.PolicyConfig;
import vn.secureproxy.policy.ScheduleMatcher;

import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;

/**
 * Thu tu uu tien:
 *  1. Nam trong allow                      -> CHO PHEP (allowlist)
 *  2. Che do WHITELIST, khong nam trong allow -> CHAN (whitelist-mode)
 *  3. Khop danh muc dang bat va dang trong khung gio -> CHAN (category:<id>)
 *  4. Khop blocklist tuy chinh             -> CHAN (custom)
 *  5. Con lai                              -> CHO PHEP (default)
 */
public class PolicyService {

    private record CompiledCategory(String id, DomainMatcher matcher,
                                    ScheduleMatcher schedule) {
    }

    private static final List<String> DEFAULT_CUSTOM = List.of(
            "facebook.com",
            "www.facebook.com",
            "tiktok.com",
            "www.tiktok.com",
            "instagram.com",
            "www.instagram.com",
            "netflix.com",
            "www.netflix.com",
            "blocked.example",
            "example.org"
    );

    private final boolean whitelistMode;
    private final ZoneId zone;
    private final Clock clock;
    private final DomainMatcher allowMatcher;
    private final DomainMatcher customMatcher;
    private final DomainMatcher phishingMatcher;
    private final DomainMatcher adsTrackerMatcher;
    private final List<CompiledCategory> categories = new ArrayList<>();

    /** Giu nguyen hanh vi cu: chi chan 10 ten mien mac dinh. */
    public PolicyService() {
        this(new PolicyConfig(null, null, null, null), DEFAULT_CUSTOM, Clock.systemUTC());
    }

    public PolicyService(PolicyConfig config, Collection<String> customBlocklist) {
        this(config, customBlocklist, List.of(), List.of(), Clock.systemUTC());
    }

    public PolicyService(PolicyConfig config, Collection<String> customBlocklist,
                         Clock clock) {
        this(config, customBlocklist, List.of(), List.of(), clock);
    }

    public PolicyService(
            PolicyConfig config,
            Collection<String> customBlocklist,
            Collection<String> phishingBlocklist,
            Collection<String> adsTrackerBlocklist
    ) {
        this(config, customBlocklist, phishingBlocklist, adsTrackerBlocklist, Clock.systemUTC());
    }

    public PolicyService(
            PolicyConfig config,
            Collection<String> customBlocklist,
            Collection<String> phishingBlocklist,
            Collection<String> adsTrackerBlocklist,
            Clock clock
    ) {
        this.whitelistMode = config.isWhitelistMode();
        this.zone = resolveZone(config.timezone());
        this.clock = clock;
        this.allowMatcher = new DomainMatcher(config.allow());
        this.customMatcher = new DomainMatcher(customBlocklist);
        this.phishingMatcher = new DomainMatcher(phishingBlocklist);
        this.adsTrackerMatcher = new DomainMatcher(adsTrackerBlocklist);

        for (PolicyConfig.Category c : config.categories()) {
            if (!c.active()) {
                continue;
            }
            ScheduleMatcher schedule = c.schedule().isEmpty()
                    ? null : new ScheduleMatcher(c.schedule());
            categories.add(new CompiledCategory(
                    c.id(), new DomainMatcher(c.patterns()), schedule));
        }
    }

    private static ZoneId resolveZone(String id) {
        try {
            return ZoneId.of(id);
        } catch (DateTimeException e) {
            System.err.println("[PolicyService] Mui gio khong hop le: " + id
                    + " -> dung Asia/Ho_Chi_Minh");
            return ZoneId.of("Asia/Ho_Chi_Minh");
        }
    }

    public boolean choPhep(String host) {
        return danhGia(host).allowed();
    }

    public Decision danhGia(String host) {
        String h = chuanHoa(host);
        if (h == null) {
            return Decision.block("invalid-host");
        }

        if (phishingMatcher.matches(h)) {
            return Decision.block("phishing-feed");
        }

        if (allowMatcher.matches(h)) {
            return Decision.allow("allowlist");
        }

        if (whitelistMode) {
            return Decision.block("whitelist-mode");
        }

        ZonedDateTime now = Instant.now(clock).atZone(zone);

        for (CompiledCategory c : categories) {
            if (c.matcher().matches(h)
                    && (c.schedule() == null || c.schedule().matches(now))) {
                return Decision.block("category:" + c.id());
            }
        }

        if (customMatcher.matches(h)) {
            return Decision.block("custom");
        }

        if (adsTrackerMatcher.matches(h)) {
            return Decision.block("ads-tracker-feed");
        }

        return Decision.allow("default");
    }

    /** Chu thuong, bo cong, bo dau cham cuoi, xu ly dang [IPv6]:cong. */
    static String chuanHoa(String host) {
        if (host == null) {
            return null;
        }

        String h = host.trim().toLowerCase(Locale.ROOT);
        if (h.isEmpty()) {
            return null;
        }

        if (h.startsWith("[")) {
            int end = h.indexOf(']');
            h = end > 0 ? h.substring(1, end) : h.substring(1);
        } else if (h.indexOf(':') >= 0 && h.indexOf(':') == h.lastIndexOf(':')) {
            h = h.substring(0, h.indexOf(':'));
        }

        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }

        return h.isEmpty() ? null : h;
    }
}