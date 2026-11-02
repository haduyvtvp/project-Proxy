package vn.secureproxy.policy;

import com.fasterxml.jackson.databind.ObjectMapper;
import vn.secureproxy.PolicyService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Kho chinh sach dung chung cho toan proxy.
 * Doc policy.json + blocklist.txt trong thu muc du lieu, tu nap lai khi file doi.
 */
public class PolicyStore {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static volatile PolicyStore shared;

    /** Ban dung chung: thu muc lay tu bien moi truong DATA_DIR (mac dinh /data). */
    public static PolicyStore shared() {
        PolicyStore s = shared;
        if (s == null) {
            synchronized (PolicyStore.class) {
                s = shared;
                if (s == null) {
                    String dir = System.getenv("DATA_DIR");
                    if (dir == null || dir.isBlank()) {
                        dir = "/data";
                    }
                    s = new PolicyStore(Paths.get(dir), 5000);
                    shared = s;
                }
            }
        }
        return s;
    }

    private final Path policyFile;
    private final Path blocklistFile;
    private final Path phishingFile;
    private final Path adsTrackerFile;
    private volatile PolicyService current;
    private String lastSignature = "";
    private String lastErrorSignature = "";

    public PolicyStore(Path dataDir, long intervalMillis) {
        this.policyFile = dataDir.resolve("policy.json");
        this.blocklistFile = dataDir.resolve("blocklist.txt");
        this.phishingFile = dataDir.resolve("phishing-domains.txt");
        this.adsTrackerFile = dataDir.resolve("ads-trackers.txt");
        this.current = new PolicyService();

        reloadIfChanged();

        ScheduledExecutorService scheduler =
                Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "policy-reload");
                    t.setDaemon(true);
                    return t;
                });
        scheduler.scheduleWithFixedDelay(
                this::reloadIfChanged, intervalMillis, intervalMillis,
                TimeUnit.MILLISECONDS);
    }

    public PolicyService current() {
        return current;
    }

    private static String signature(Path p) {
        try {
            if (!Files.isRegularFile(p)) {
                return "none";
            }
            return Files.getLastModifiedTime(p).toMillis() + ":" + Files.size(p);
        } catch (IOException e) {
            return "err";
        }
    }

    private static List<String> readLines(Path file) throws IOException {
        List<String> out = new ArrayList<>();
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            String d = line.trim();
            if (!d.isEmpty() && !d.startsWith("#")) {
                out.add(d);
            }
        }
        return out;
    }

    private synchronized void reloadIfChanged() {
        String sig = signature(policyFile) + "|" + signature(blocklistFile)
                + "|" + signature(phishingFile) + "|" + signature(adsTrackerFile);
        if (sig.equals(lastSignature)) {
            return;
        }

        try {
            boolean hasPolicy = Files.isRegularFile(policyFile);
            boolean hasBlocklist = Files.isRegularFile(blocklistFile);
            boolean hasPhishingFeed = Files.isRegularFile(phishingFile);
            boolean hasAdsTrackerFeed = Files.isRegularFile(adsTrackerFile);

            PolicyService next;
            String info;

            if (!hasPolicy && !hasBlocklist) {
                next = new PolicyService();
                info = "khong co file, dung danh sach mac dinh";
            } else {
                PolicyConfig cfg = hasPolicy
                        ? MAPPER.readValue(policyFile.toFile(), PolicyConfig.class)
                        : new PolicyConfig(null, null, null, null);
                List<String> custom = hasBlocklist
                        ? readLines(blocklistFile) : List.of();
                List<String> phishing = hasPhishingFeed
                        ? readLines(phishingFile) : List.of();
                List<String> adsTrackers = hasAdsTrackerFeed
                        ? readLines(adsTrackerFile) : List.of();

                next = new PolicyService(cfg, custom, phishing, adsTrackers);
                info = "mode=" + cfg.mode()
                        + ", " + cfg.categories().size() + " danh muc"
                        + ", " + custom.size() + " ten mien tuy chinh"
                        + ", " + phishing.size() + " phishing"
                        + ", " + adsTrackers.size() + " ads/tracker";
            }

            current = next;
            lastSignature = sig;
            lastErrorSignature = "";
            System.out.println("[PolicyStore] Da nap chinh sach: " + info);

        } catch (Exception e) {
            // Giu nguyen ban cu; chi in loi 1 lan cho moi trang thai file
            if (!sig.equals(lastErrorSignature)) {
                lastErrorSignature = sig;
                System.err.println("[PolicyStore] Loi doc chinh sach, giu ban cu: "
                        + e.getMessage());
            }
        }
    }
}