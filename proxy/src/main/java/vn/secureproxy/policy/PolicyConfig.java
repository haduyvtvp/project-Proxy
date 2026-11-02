package vn.secureproxy.policy;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record PolicyConfig(
        String mode,              // BLOCKLIST hoặc WHITELIST
        String timezone,          // ví dụ Asia/Ho_Chi_Minh
        List<String> allow,       // tên miền luôn được phép (hoặc được phép trong chế độ WHITELIST)
        List<Category> categories
) {

    public PolicyConfig {
        mode = (mode == null || mode.isBlank()) ? "BLOCKLIST" : mode.trim().toUpperCase();
        timezone = (timezone == null || timezone.isBlank()) ? "Asia/Ho_Chi_Minh" : timezone.trim();
        allow = (allow == null) ? List.of() : List.copyOf(allow);
        categories = (categories == null) ? List.of() : List.copyOf(categories);
    }

    public boolean isWhitelistMode() {
        return "WHITELIST".equals(mode);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Category(
            String id,
            String name,
            Boolean enabled,          // không ghi thì coi như bật
            List<String> patterns,    // "a.com", "*.a.com", "regex:..."
            List<Schedule> schedule   // rỗng = chặn cả ngày
    ) {
        public Category {
            patterns = (patterns == null) ? List.of() : List.copyOf(patterns);
            schedule = (schedule == null) ? List.of() : List.copyOf(schedule);
        }

        public boolean active() {
            return enabled == null || enabled;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public record Schedule(
            List<String> days,        // MON, TUE, WED, THU, FRI, SAT, SUN (rỗng = mọi ngày)
            String from,              // "07:30"
            String to                 // "11:30"
    ) {
        public Schedule {
            days = (days == null) ? List.of() : List.copyOf(days);
        }
    }
}