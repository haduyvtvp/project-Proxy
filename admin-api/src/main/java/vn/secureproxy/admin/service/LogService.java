package vn.secureproxy.admin.service;

import org.springframework.stereotype.Service;
import vn.secureproxy.admin.model.LogEntry;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
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
            " Result=(.+)"
    );

    // Circular buffer for in-memory log entries
    private final Deque<LogEntry> buffer = new ArrayDeque<>(BUFFER_SIZE);

    // SSE subscribers
    private final List<BlockingQueue<LogEntry>> subscribers = new CopyOnWriteArrayList<>();

    public LogService() {
        loadExistingLogs();
        startTailThread();
    }

    private void loadExistingLogs() {
        File logFile = new File(LOG_FILE);
        if (!logFile.exists()) return;
        try (BufferedReader reader = new BufferedReader(new FileReader(logFile))) {
            String line;
            while ((line = reader.readLine()) != null) {
                LogEntry entry = parseLine(line);
                if (entry != null) addToBuffer(entry);
            }
        } catch (IOException e) {
            System.err.println("[LogService] Failed to load existing logs: " + e.getMessage());
        }
    }

    private void startTailThread() {
        Thread tailThread = new Thread(() -> {
            File logFile = new File(LOG_FILE);
            // Wait until file appears
            while (!logFile.exists()) {
                try { Thread.sleep(2000); } catch (InterruptedException ie) { return; }
            }
            try (RandomAccessFile raf = new RandomAccessFile(logFile, "r")) {
                // Seek to end of existing content
                raf.seek(raf.length());
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
        for (BlockingQueue<LogEntry> queue : subscribers) {
            queue.offer(entry);
        }
    }

    public synchronized List<LogEntry> getRecentLogs(int limit) {
        List<LogEntry> list = new ArrayList<>(buffer);
        int fromIndex = Math.max(0, list.size() - limit);
        return list.subList(fromIndex, list.size());
    }

    public synchronized List<LogEntry> getAllLogs() {
        return new ArrayList<>(buffer);
    }

    public BlockingQueue<LogEntry> subscribe() {
        BlockingQueue<LogEntry> queue = new LinkedBlockingQueue<>();
        subscribers.add(queue);
        return queue;
    }

    public void unsubscribe(BlockingQueue<LogEntry> queue) {
        subscribers.remove(queue);
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
                m.group(5).trim(),
                line.trim()
        );
    }
}
