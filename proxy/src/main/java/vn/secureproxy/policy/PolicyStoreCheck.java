package vn.secureproxy.policy;

import java.nio.file.Files;
import java.nio.file.Path;

public class PolicyStoreCheck {

    private static int pass = 0;
    private static int fail = 0;

    private static void check(String name, Decision got, boolean allowed, String reason) {
        boolean ok = got.allowed() == allowed && got.reason().equals(reason);
        if (ok) {
            pass++;
        } else {
            fail++;
        }
        System.out.println((ok ? "PASS " : "FAIL ") + name
                + (ok ? "" : "  (mong doi " + allowed + "/" + reason
                + ", nhan duoc " + got.allowed() + "/" + got.reason() + ")"));
    }

    public static void main(String[] args) throws Exception {
        Path dir = Files.createTempDirectory("policy-check");

        String json1 = """
                {"mode":"BLOCKLIST","timezone":"Asia/Ho_Chi_Minh",
                 "allow":["ok.facebook.com"],
                 "categories":[{"id":"social","name":"Mang xa hoi","enabled":true,
                                "patterns":["facebook.com"],"schedule":[]}]}
                """;
        String json2 = """
                {"mode":"WHITELIST","allow":["wikipedia.org"],"categories":[]}
                """;

        // 1. Chua co file nao -> hanh vi cu
        PolicyStore store = new PolicyStore(dir, 300);
        check("khong co file: netflix bi chan (mac dinh)",
                store.current().danhGia("netflix.com"), false, "custom");
        check("khong co file: google cho phep",
                store.current().danhGia("google.com"), true, "default");

        // 2. Ghi blocklist.txt + policy.json -> tu nap lai
        Files.writeString(dir.resolve("blocklist.txt"), "# ghi chu\nabc.xyz\n");
        Files.writeString(dir.resolve("policy.json"), json1);
        Thread.sleep(1000);
        check("nap file: facebook.com theo danh muc",
                store.current().danhGia("facebook.com"), false, "category:social");
        check("nap file: allow thang danh muc",
                store.current().danhGia("ok.facebook.com"), true, "allowlist");
        check("nap file: abc.xyz trong blocklist.txt",
                store.current().danhGia("abc.xyz"), false, "custom");
        check("nap file: google cho phep",
                store.current().danhGia("google.com"), true, "default");

        // 3. Sua thanh WHITELIST -> tu nap lai
        Files.writeString(dir.resolve("policy.json"), json2);
        Thread.sleep(1000);
        check("doi sang WHITELIST: google bi chan",
                store.current().danhGia("google.com"), false, "whitelist-mode");
        check("doi sang WHITELIST: wikipedia duoc phep",
                store.current().danhGia("vi.wikipedia.org"), true, "allowlist");

        // 4. File hong -> giu ban cu
        Files.writeString(dir.resolve("policy.json"), "{ khong phai json");
        Thread.sleep(1000);
        check("file hong: van giu ban cu (WHITELIST)",
                store.current().danhGia("google.com"), false, "whitelist-mode");

        // 5. Sua lai dung -> nap lai binh thuong
        Files.writeString(dir.resolve("policy.json"), json1);
        Thread.sleep(1000);
        check("sua lai dung: nap lai binh thuong",
                store.current().danhGia("facebook.com"), false, "category:social");

        System.out.println();
        System.out.println("PASS: " + pass + "  FAIL: " + fail);
    }
}