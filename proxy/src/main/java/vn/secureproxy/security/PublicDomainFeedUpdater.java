package vn.secureproxy.security;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public final class PublicDomainFeedUpdater {

    private static final URI PHISHING_FEED =
            URI.create("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt");
    private static final URI ADS_TRACKER_FEED =
            URI.create("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts");
    private static final int MAX_FEED_BYTES = 64 * 1024 * 1024;
    private static final int MIN_AD_TRACKER_DOMAINS = 100;
    private static final int MIN_PHISHING_DOMAINS = 1;
    private static final int MAX_DOMAINS = 1_000_000;

    private final Path dataDirectory;
    private final HttpClient httpClient;

    private PublicDomainFeedUpdater(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public static void start(Path dataDirectory) {
        PublicDomainFeedUpdater updater = new PublicDomainFeedUpdater(dataDirectory);
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(task -> {
            Thread thread = new Thread(task, "public-domain-feed-updater");
            thread.setDaemon(true);
            return thread;
        });
        scheduler.scheduleWithFixedDelay(
                updater::refresh,
                0,
                6,
                TimeUnit.HOURS
        );
    }

    private void refresh() {
        updateFeed(PHISHING_FEED, dataDirectory.resolve("phishing-domains.txt"),
                this::parsePhishingFeed, MIN_PHISHING_DOMAINS, "phishing");
        updateFeed(ADS_TRACKER_FEED, dataDirectory.resolve("ads-trackers.txt"),
                this::parseHostsFeed, MIN_AD_TRACKER_DOMAINS, "ads/tracker");
    }

    private void updateFeed(
            URI uri,
            Path destination,
            FeedParser parser,
            int minimumDomains,
            String label
    ) {
        try {
            byte[] content = download(uri);
            Set<String> domains = parser.parse(new String(content, StandardCharsets.UTF_8));
            if (domains.size() < minimumDomains) {
                throw new IOException("Feed contained only " + domains.size() + " valid domains");
            }
            writeAtomically(destination, domains);
            System.out.println("[DomainFeeds] Updated " + label + " feed with "
                    + domains.size() + " domains");
        } catch (IOException e) {
            System.err.println("[DomainFeeds] Could not update " + label
                    + " feed; keeping the last valid copy: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("[DomainFeeds] Update interrupted for " + label + " feed");
        }
    }

    private byte[] download(URI uri) throws IOException, InterruptedException {
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getUserInfo() != null
                || uri.getHost() == null) {
            throw new IOException("Feed URL must be an HTTPS URL without credentials");
        }

        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(45))
                .header("User-Agent", "SecureProxy-DomainFeedUpdater/1.0")
                .GET()
                .build();
        HttpResponse<InputStream> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            if (response.statusCode() != 200) {
                throw new IOException("Feed server returned HTTP " + response.statusCode());
            }
            byte[] content = body.readNBytes(MAX_FEED_BYTES + 1);
            if (content.length > MAX_FEED_BYTES) {
                throw new IOException("Feed exceeded the 64 MiB size limit");
            }
            return content;
        }
    }

    private Set<String> parsePhishingFeed(String content) {
        Set<String> domains = new LinkedHashSet<>();
        for (String line : content.split("\\R")) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            try {
                URI entry = URI.create(value.contains("://") ? value : "https://" + value);
                addDomain(domains, entry.getHost());
            } catch (IllegalArgumentException ignored) {
                // Individual malformed feed entries do not invalidate a feed update.
            }
        }
        return domains;
    }

    private Set<String> parseHostsFeed(String content) {
        Set<String> domains = new LinkedHashSet<>();
        for (String line : content.split("\\R")) {
            String value = line.trim();
            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }
            String[] fields = value.split("\\s+");
            if (fields.length < 2 || !isIpLiteral(fields[0])) {
                continue;
            }
            for (int i = 1; i < fields.length; i++) {
                addDomain(domains, fields[i]);
                if (domains.size() >= MAX_DOMAINS) {
                    return domains;
                }
            }
        }
        return domains;
    }

    private static void addDomain(Set<String> domains, String raw) {
        if (raw == null) {
            return;
        }
        String domain = raw.toLowerCase(Locale.ROOT);
        while (domain.endsWith(".")) {
            domain = domain.substring(0, domain.length() - 1);
        }
        if (domain.length() > 253
                || !domain.contains(".")
                || domain.equals("localhost")
                || domain.matches("[0-9.]+")
                || !domain.matches("(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?")) {
            return;
        }
        domains.add(domain);
    }

    private static boolean isIpLiteral(String value) {
        return value.matches("[0-9.]+") || value.contains(":");
    }

    private static void writeAtomically(Path destination, Set<String> domains) throws IOException {
        Files.createDirectories(destination.toAbsolutePath().getParent());
        Path temporary = Files.createTempFile(
                destination.toAbsolutePath().getParent(), "domain-feed-", ".tmp");
        try {
            Files.write(temporary, domains, StandardCharsets.UTF_8);
            try {
                Files.move(temporary, destination,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, destination, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    @FunctionalInterface
    private interface FeedParser {
        Set<String> parse(String content);
    }
}
