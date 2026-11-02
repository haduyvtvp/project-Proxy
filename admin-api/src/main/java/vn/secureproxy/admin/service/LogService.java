package vn.secureproxy.admin.service;

import org.springframework.stereotype.Service;
import vn.secureproxy.admin.model.LogEntry;
import vn.secureproxy.admin.model.LogPage;
import vn.secureproxy.admin.model.MonitoringSnapshot;
import vn.secureproxy.admin.repository.LogRepository;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.regex.*;

@Service
public class LogService {

    private static final String LOG_FILE = "/data/access.log";
    private static final int BUFFER_SIZE = 1000;
        private static final Pattern LOG_PATTERN = Pattern.compile(
            "\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\]" +
            " Client=([^ ]+)" +
            " Host=([^ ]+)" +
            " Method=([^ ]+)" +
            " Result=([^ ]+)" +
            "(?: Reason=([^ ]+))?" +
            ".*"
    );

    // Circular buffer for in-memory log entries
    private final Deque<LogEntry> buffer = new ArrayDeque<>(BUFFER_SIZE);

    private final List<Consumer<LogEntry>> subscribers = new CopyOnWriteArrayList<>();
    private final LogRepository logRepository;

    public LogService(LogRepository logRepository) {
        this.logRepository = logRepository;
        File logFile = new File(LOG_FILE);
        long initialLogLength = logFile.exists() ? logFile.length() : 0;
        loadExistingLogs();
        startTailThread(initialLogLength);
    }

    private void loadExistingLogs() {
        File logFile = new File(LOG_FILE);
        if (!logFile.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            List<LogEntry> batch = new ArrayList<>(500);
            while ((line = reader.readLine()) != null) {
                LogEntry entry = parseLine(line);
                if (entry != null) {
                    addToBuffer(entry);
                    batch.add(entry);
                    if (batch.size() == 500) {
                        logRepository.saveAll(batch);
                        batch.clear();
                    }
                }
            }
            logRepository.saveAll(batch);
        } catch (IOException e) {
            System.err.println("[LogService] Failed to load existing logs: " + e.getMessage());
        }
    }

    private void startTailThread(long initialLogLength) {
        Thread tailThread = new Thread(() -> {
            File logFile = new File(LOG_FILE);
            // Wait until file appears
            while (!logFile.exists()) {
                try { Thread.sleep(2000); } catch (InterruptedException ie) { return; }
            }
            try (RandomAccessFile raf = new RandomAccessFile(logFile, "r")) {
                raf.seek(Math.min(initialLogLength, raf.length()));
                while (!Thread.currentThread().isInterrupted()) {
                    String line = raf.readLine();
                    if (line == null) {
                        // Check for file rotation
                        if (raf.length() < raf.getFilePointer()) {
                            raf.seek(0);
                        }
                        Thread.sleep(500);
                    } else {
                        LogEntry entry = parseLine(line);
                        if (entry != null) {
                            logRepository.save(entry);
                            addToBuffer(entry);
                            broadcastToSubscribers(entry);
                        }
                    }
                }
            } catch (IOException | InterruptedException e) {
                System.err.println("[LogService] Tail thread error: " + e.getMessage());
            }
        }, "log-tail-thread");
        tailThread.setDaemon(true);
        tailThread.start();
    }

    private synchronized void addToBuffer(LogEntry entry) {
        if (buffer.size() >= BUFFER_SIZE) {
            buffer.pollFirst();
        }
        buffer.addLast(entry);
    }

    private void broadcastToSubscribers(LogEntry entry) {
        for (Consumer<LogEntry> subscriber : subscribers) {
            subscriber.accept(entry);
        }
    }

    public synchronized List<LogEntry> getRecentLogs(int limit) {
        return logRepository.findRecent(limit);
    }

    public List<LogEntry> getAllLogs() {
        return logRepository.findAll();
    }

    public MonitoringSnapshot getMonitoring(
            LocalDateTime from,
            LocalDateTime to,
            int bucketMinutes
    ) {
        return logRepository.findMonitoring(from, to, bucketMinutes);
    }

    public LogPage searchLogs(
            LocalDateTime from,
            LocalDateTime to,
            String client,
            String host,
            int page,
            int size
    ) {
        return logRepository.findFiltered(from, to, client, host, page, size);
    }

    public void subscribe(Consumer<LogEntry> subscriber) {
        subscribers.add(subscriber);
    }

    public void unsubscribe(Consumer<LogEntry> subscriber) {
        subscribers.remove(subscriber);
    }

    public static LogEntry parseLine(String line) {
        if (line == null || line.isBlank()) return null;
        Matcher m = LOG_PATTERN.matcher(line.trim());
        if (!m.matches()) return null;
        return new LogEntry(
                m.group(1),
                m.group(2),
                m.group(3),
                m.group(4),
                m.group(5),
                m.group(6),
                line.trim()
        );
    }
}
