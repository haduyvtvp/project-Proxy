package vn.secureproxy.admin.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import vn.secureproxy.admin.model.MonitoringSnapshot;
import vn.secureproxy.admin.service.LogService;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Map;

@RestController
@RequestMapping("/api/monitoring")
public class MonitoringController {

    private final LogService logService;

    public MonitoringController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping
    public MonitoringSnapshot getMonitoring(
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "5") int bucketMinutes
    ) {
        LocalDateTime end = to == null
                ? LocalDateTime.now(ZoneId.of("Asia/Ho_Chi_Minh")) : to;
        LocalDateTime start = from == null ? end.minusHours(1) : from;
        validateRange(start, end, bucketMinutes);
        return logService.getMonitoring(start, end, bucketMinutes);
    }

    private static void validateRange(LocalDateTime from, LocalDateTime to, int bucketMinutes) {
        if (!from.isBefore(to)) {
            throw new IllegalArgumentException("'from' must be earlier than 'to'");
        }
        if (Duration.between(from, to).compareTo(Duration.ofDays(31)) > 0) {
            throw new IllegalArgumentException("Monitoring range cannot exceed 31 days");
        }
        if (bucketMinutes < 1 || bucketMinutes > 1440) {
            throw new IllegalArgumentException("bucketMinutes must be between 1 and 1440");
        }
    }

    @org.springframework.web.bind.annotation.ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleInvalidRange(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
    }
}
