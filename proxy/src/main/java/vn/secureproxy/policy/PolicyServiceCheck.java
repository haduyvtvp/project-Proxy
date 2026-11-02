package vn.secureproxy.policy;

import vn.secureproxy.PolicyService;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;

public class PolicyServiceCheck {

    private static final ZoneId VN = ZoneId.of("Asia/Ho_Chi_Minh");
    private static int pass = 0;
    private static int fail = 0;

    // day: ngay trong thang 11/2026 (2 = Thu Hai, 3 = Thu Ba, 7 = Thu Bay)
    private static PolicyService at(PolicyConfig cfg, List<String> custom,
                                    int day, int hour, int minute) {
        Instant t = ZonedDateTime.of(2026, 11, day, hour, minute, 0, 0, VN).toInstant();
        return new PolicyService(cfg, custom, Clock.fixed(t, ZoneOffset.UTC));
    }

    private static void check(String name, Decision got, boolean allowed, String reason) {
        boolean ok = got.allowed() == allowed && got.reason().equals(reason);
        if (ok) {
            pass++;
        } else {
            fail++;
        }
        System.out.println((ok ? "PASS " : "FAIL ") + name
                + (ok ? "" : "  (mong doi " + allowed + "/" + reason
                + ", nhan duoc " + got.allowed() + "/" + got.reason() + ")"));
    }

    public static void main(String[] args) {
        PolicyConfig cfg = new PolicyConfig("BLOCKLIST", "Asia/Ho_Chi_Minh",
                List.of("allowed.facebook.com"),
                List.of(
                        new PolicyConfig.Category("social", "Mang xa hoi", true,
                                List.of("facebook.com", "*.fbcdn.net",
                                        "regex:^.*\\.tiktokcdn.*\\.com$"),
                                List.of()),
                        new PolicyConfig.Category("game", "Game", true,
                                List.of("roblox.com"),
                                List.of(new PolicyConfig.Schedule(
                                        List.of("MON", "TUE", "WED", "THU", "FRI"),
                                        "07:30", "11:30"))),
                        new PolicyConfig.Category("off", "Tat", false,
                                List.of("off.com"), List.of()),
                        new PolicyConfig.Category("night", "Dem", true,
                                List.of("night.com"),
                                List.of(new PolicyConfig.Schedule(
                                        List.of("MON"), "22:00", "06:00")))
                ));

        // --- Danh muc, wildcard, regex, uu tien ---
        PolicyService s = at(cfg, List.of(), 2, 8, 0);
        check("facebook.com bi chan", s.danhGia("facebook.com"), false, "category:social");
        check("www.facebook.com bi chan", s.danhGia("www.facebook.com"), false, "category:social");
        check("allow thang danh muc", s.danhGia("allowed.facebook.com"), true, "allowlist");
        check("*.fbcdn.net khop ten mien phu", s.danhGia("x.fbcdn.net"), false, "category:social");
        check("*.fbcdn.net khong khop ten mien goc", s.danhGia("fbcdn.net"), true, "default");
        check("regex tiktokcdn", s.danhGia("v16.tiktokcdn-us.com"), false, "category:social");
        check("ten mien khong lien quan", s.danhGia("example.com"), true, "default");
        check("danh muc tat khong chan", s.danhGia("off.com"), true, "default");
        check("host co cong", s.danhGia("facebook.com:443"), false, "category:social");
        check("host rong", s.danhGia(null), false, "invalid-host");

        // --- Khung gio ---
        check("game T2 08:00 (trong gio)", at(cfg, List.of(), 2, 8, 0).danhGia("roblox.com"), false, "category:game");
        check("game T2 12:00 (ngoai gio)", at(cfg, List.of(), 2, 12, 0).danhGia("roblox.com"), true, "default");
        check("game T7 08:00 (ngoai ngay)", at(cfg, List.of(), 7, 8, 0).danhGia("roblox.com"), true, "default");
        check("dem T2 23:00", at(cfg, List.of(), 2, 23, 0).danhGia("night.com"), false, "category:night");
        check("dem T3 05:00 (qua nua dem)", at(cfg, List.of(), 3, 5, 0).danhGia("night.com"), false, "category:night");
        check("dem T3 07:00 (het gio)", at(cfg, List.of(), 3, 7, 0).danhGia("night.com"), true, "default");
        check("dem T2 05:00 (chua den gio)", at(cfg, List.of(), 2, 5, 0).danhGia("night.com"), true, "default");

        // --- Blocklist tuy chinh ---
        check("custom blocklist", at(cfg, List.of("abc.xyz"), 2, 8, 0).danhGia("www.abc.xyz"), false, "custom");

        // --- Che do WHITELIST ---
        PolicyConfig wl = new PolicyConfig("WHITELIST", "Asia/Ho_Chi_Minh",
                List.of("wikipedia.org"), List.of());
        PolicyService w = at(wl, List.of(), 2, 8, 0);
        check("whitelist: trang duoc phep", w.danhGia("vi.wikipedia.org"), true, "allowlist");
        check("whitelist: trang khac bi chan", w.danhGia("google.com"), false, "whitelist-mode");

        // --- Hanh vi cu (constructor khong tham so) ---
        PolicyService old = new PolicyService();
        check("mac dinh: netflix bi chan", old.danhGia("www.netflix.com"), false, "custom");
        check("mac dinh: sub.example.org bi chan", old.danhGia("sub.example.org"), false, "custom");
        check("mac dinh: google cho phep", old.danhGia("google.com"), true, "default");

        System.out.println();
        System.out.println("PASS: " + pass + "  FAIL: " + fail);
    }
}