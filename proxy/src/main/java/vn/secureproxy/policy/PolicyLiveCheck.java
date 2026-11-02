package vn.secureproxy.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import vn.secureproxy.PolicyService;

import java.io.File;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.List;

/** Kiem tra theo GIO THUC: doc policy.sample.json, danh gia tung ten mien ngay bay gio. */
public class PolicyLiveCheck {

    public static void main(String[] args) throws Exception {
        File file = null;
        for (String c : new String[]{"proxy/policy.sample.json", "policy.sample.json"}) {
            if (new File(c).isFile()) {
                file = new File(c);
                break;
            }
        }
        if (file == null) {
            System.err.println("Khong tim thay policy.sample.json");
            return;
        }

        PolicyConfig cfg = new ObjectMapper().readValue(file, PolicyConfig.class);
        PolicyService service = new PolicyService(cfg, List.of());

        System.out.println("File: " + file.getAbsolutePath());
        System.out.println("Gio hien tai: "
                + ZonedDateTime.now(ZoneId.of(cfg.timezone())));
        System.out.println();

        List<String> hosts = args.length > 0
                ? List.of(args)
                : List.of("facebook.com", "www.tiktok.com", "netflix.com",
                "roblox.com", "vnexpress.net", "google.com");

        for (String h : hosts) {
            Decision d = service.danhGia(h);
            System.out.println((d.allowed() ? "CHO PHEP  " : "CHAN      ")
                    + h + "  (" + d.reason() + ")");
        }
    }
}