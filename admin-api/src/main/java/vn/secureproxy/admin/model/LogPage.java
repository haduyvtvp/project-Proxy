package vn.secureproxy.admin.model;

import java.util.List;

public record LogPage(
        List<LogEntry> entries,
        int page,
        int size,
        long total
) {
}
