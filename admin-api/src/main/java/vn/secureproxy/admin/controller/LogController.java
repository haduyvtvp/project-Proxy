package vn.secureproxy.admin.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.format.annotation.DateTimeFormat;
import vn.secureproxy.admin.model.LogEntry;
import vn.secureproxy.admin.model.LogPage;
import vn.secureproxy.admin.service.LogService;

import java.time.Duration;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/logs")
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping
    public List<LogEntry> getLogs(@RequestParam(defaultValue = "100") int limit) {
        return logService.getRecentLogs(limit);
    }

    @GetMapping("/search")
    public LogPage searchLogs(
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime from,
            @RequestParam(required = false)
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime to,
            @RequestParam(defaultValue = "") String client,
            @RequestParam(defaultValue = "") String host,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        LocalDateTime end = to == null
                ? LocalDateTime.now(ZoneId.of("Asia/Ho_Chi_Minh")).plusSeconds(1)
                : to.plusMinutes(1);
        LocalDateTime start = from == null ? end.minusDays(1) : from;
        if (!start.isBefore(end)) {
            throw new IllegalArgumentException("'from' must be earlier than 'to'");
        }
        if (Duration.between(start, end).compareTo(Duration.ofDays(90)) > 0) {
            throw new IllegalArgumentException("Log search range cannot exceed 90 days");
        }
        if (page < 0 || size < 1 || size > 200) {
            throw new IllegalArgumentException("page must be non-negative and size must be between 1 and 200");
        }
        return logService.searchLogs(start, end, client.trim(), host.trim(), page, size);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleInvalidSearch(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
    }
}
