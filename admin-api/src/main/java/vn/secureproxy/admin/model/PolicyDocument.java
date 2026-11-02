package vn.secureproxy.admin.model;

import java.util.List;

public record PolicyDocument(
        String mode,
        String timezone,
        List<String> allow,
        List<Category> categories
) {

    public record Category(
            String id,
            String name,
            Boolean enabled,
            List<String> patterns,
            List<Schedule> schedule
    ) {
    }

    public record Schedule(
            List<String> days,
            String from,
            String to
    ) {
    }
}
