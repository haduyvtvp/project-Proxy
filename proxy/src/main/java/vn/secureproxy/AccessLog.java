package vn.secureproxy;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.ZoneId;


public class AccessLog {

    private static final String LOG_FILE = "/data/access.log";
    private static final DateTimeFormatter FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final ZoneId ZONE = ZoneId.of("Asia/Ho_Chi_Minh");

    /** Ban cu: khong ghi ly do. */
    public static void ghiLog(
            String clientIp,
            String host,
            String method,
            String result) {

        ghiLog(clientIp, host, method, result, null);
    }

    /** Ban moi: them Reason o cuoi dong, vi du Reason=category:social. */
    public static void ghiLog(
            String clientIp,
            String host,
            String method,
            String result,
            String reason) {

        String thoiGian = LocalDateTime.now(ZONE).format(FORMATTER);

        String logLine = "[" + thoiGian + "]"
                + " Client=" + clientIp
                + " Host=" + host
                + " Method=" + method
                + " Result=" + result;

        if (reason != null && !reason.isBlank()) {
            // Reason khong duoc co khoang trang de de tach khi doc log
            logLine += " Reason=" + reason.trim().replaceAll("\\s+", "_");
        }

        // 1. Ghi ra stdout (giu nguyen)
        System.out.println(logLine);

        // 2. Ghi append vao /data/access.log
        try (PrintWriter pw = new PrintWriter(new FileWriter(LOG_FILE, true))) {
            pw.println(logLine);
        } catch (IOException e) {
            System.err.println("[AccessLog] Cannot write to " + LOG_FILE + ": " + e.getMessage());
        }
    }
}