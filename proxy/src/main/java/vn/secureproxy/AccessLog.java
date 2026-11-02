
package vn.secureproxy;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class AccessLog {

    private static final String LOG_FILE = "/data/access.log";
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static void ghiLog(
            String clientIp,
            String host,
            String method,
            String result) {

        String thoiGian = LocalDateTime.now().format(FORMATTER);

        String logLine = "[" + thoiGian + "]"
                + " Client=" + clientIp
                + " Host=" + host
                + " Method=" + method
                + " Result=" + result;

        // 1. Ghi ra stdout (giữ nguyên)
        System.out.println(logLine);

        // 2. Ghi append vào /data/access.log
        try (PrintWriter pw = new PrintWriter(new FileWriter(LOG_FILE, true))) {
            pw.println(logLine);
        } catch (IOException e) {
            System.err.println("[AccessLog] Cannot write to " + LOG_FILE + ": " + e.getMessage());
        }
    }
}

