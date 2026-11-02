package vn.secureproxy.admin.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import org.springframework.http.codec.ServerSentEvent;
import vn.secureproxy.admin.model.LogEntry;
import vn.secureproxy.admin.service.LogService;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.BlockingQueue;

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

    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<LogEntry>> streamLogs() {
        BlockingQueue<LogEntry> queue = logService.subscribe();

        return Flux.<ServerSentEvent<LogEntry>>create(sink -> {
            sink.onDispose(() -> logService.unsubscribe(queue));

            Thread thread = new Thread(() -> {
                try {
                    while (!sink.isCancelled()) {
                        LogEntry entry = queue.poll(1, java.util.concurrent.TimeUnit.SECONDS);
                        if (entry != null) {
                            sink.next(ServerSentEvent.<LogEntry>builder()
                                    .event("log")
                                    .data(entry)
                                    .build());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    logService.unsubscribe(queue);
                }
            }, "sse-log-thread");
            thread.setDaemon(true);
            thread.start();
        }).mergeWith(
            // Heartbeat every 15s to keep connection alive
            Flux.interval(Duration.ofSeconds(15))
                .map(tick -> ServerSentEvent.<LogEntry>builder()
                        .event("heartbeat")
                        .comment("keep-alive")
                        .build())
        );
    }
}
