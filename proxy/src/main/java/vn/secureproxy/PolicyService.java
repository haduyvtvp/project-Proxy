
package vn.secureproxy;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class PolicyService {

    private final Set<String> danhSachChan = new HashSet<>(
            Arrays.asList(
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
            )
    );

    public boolean choPhep(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }

        String tenHost = host.toLowerCase().trim();

        if (tenHost.contains(":")) {
            tenHost = tenHost.substring(0, tenHost.indexOf(":"));
        }

        // Chặn cả tên miền chính và tên miền phụ
        for (String tenMien : danhSachChan) {
            if (tenHost.equals(tenMien)
                    || tenHost.endsWith("." + tenMien)) {
                return false;
            }
        }

        return true;
    }
}
