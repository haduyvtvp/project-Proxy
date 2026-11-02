package vn.secureproxy.admin.model;

import java.time.LocalDateTime;
import java.util.List;

public record MonitoringSnapshot(
        LocalDateTime from,
        LocalDateTime to,
        long total,
        long allowed,
        long blocked,
        long errors,
        List<TimeBucket> timeline,
        List<RankedValue> topDomains,
        List<RankedValue> topClients
) {

    public record TimeBucket(
            LocalDateTime timestamp,
            long total,
            long allowed,
            long blocked
    ) {
    }

    public record RankedValue(String value, long count) {
    }
}
