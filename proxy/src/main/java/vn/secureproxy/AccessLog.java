
package vn.secureproxy;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class AccessLog {

    public static void ghiLog(
            String clientIp,
            String host,
            String method,
            String result) {

        String thoiGian = LocalDateTime.now().format(
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        );

        System.out.println(
                "[" + thoiGian + "]"
                + " Client=" + clientIp
                + " Host=" + host
                + " Method=" + method
                + " Result=" + result
        );
    }
}
