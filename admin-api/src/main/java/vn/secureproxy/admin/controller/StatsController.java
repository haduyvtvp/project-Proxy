package vn.secureproxy.admin.controller;

import org.springframework.web.bind.annotation.*;
import vn.secureproxy.admin.model.LogEntry;
import vn.secureproxy.admin.model.Stats;
import vn.secureproxy.admin.model.Stats.DomainCount;
import vn.secureproxy.admin.service.LogService;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/stats")
public class StatsController {

    private final LogService logService;

    public StatsController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping
    public Stats getStats() {
        List<LogEntry> logs = logService.getAllLogs();

        long total   = logs.size();
        long allowed = logs.stream().filter(l -> "ALLOWED".equalsIgnoreCase(l.getResult())).count();
        long blocked = logs.stream().filter(l -> "BLOCKED".equalsIgnoreCase(l.getResult())).count();
        long error   = logs.stream().filter(l -> "ERROR".equalsIgnoreCase(l.getResult())).count();

        // Top 10 blocked domains — trả về List<DomainCount> để Jackson serialize đúng
        List<DomainCount> topBlocked = logs.stream()
                .filter(l -> "BLOCKED".equalsIgnoreCase(l.getResult()))
                .collect(Collectors.groupingBy(LogEntry::getHost, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(10)
                .map(e -> new DomainCount(e.getKey(), e.getValue()))
                .collect(Collectors.toList());

        return new Stats(total, allowed, blocked, error, topBlocked);
    }
}
