package vn.secureproxy.admin.service;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;

@Service
public class BlocklistService {

    private static final String BLOCKLIST_FILE = "/data/blocklist.txt";

    private final Set<String> domains = new CopyOnWriteArraySet<>();

    @PostConstruct
    public void init() {
        loadFromFile();
    }

    private void loadFromFile() {
        File file = new File(BLOCKLIST_FILE);
        if (!file.exists()) {
            // Seed with common defaults
            domains.addAll(Arrays.asList(
                    "facebook.com", "www.facebook.com",
                    "tiktok.com", "www.tiktok.com",
                    "instagram.com", "www.instagram.com",
                    "netflix.com", "www.netflix.com",
                    "blocked.example", "example.org"
            ));
            persistToFile();
            return;
        }
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String d = line.trim();
                if (!d.isEmpty() && !d.startsWith("#")) {
                    domains.add(d.toLowerCase());
                }
            }
        } catch (IOException e) {
            System.err.println("[BlocklistService] Failed to load blocklist: " + e.getMessage());
        }
    }

    private synchronized void persistToFile() {
        File file = new File(BLOCKLIST_FILE);
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        try (PrintWriter pw = new PrintWriter(new FileWriter(file, false))) {
            for (String d : new TreeSet<>(domains)) {
                pw.println(d);
            }
        } catch (IOException e) {
            System.err.println("[BlocklistService] Failed to persist blocklist: " + e.getMessage());
        }
    }

    public Set<String> getDomains() {
        return Collections.unmodifiableSet(new TreeSet<>(domains));
    }

    public boolean addDomain(String domain) {
        if (domain == null || domain.isBlank()) return false;
        String d = domain.toLowerCase().trim();
        boolean added = domains.add(d);
        if (added) persistToFile();
        return added;
    }

    public boolean removeDomain(String domain) {
        if (domain == null || domain.isBlank()) return false;
        boolean removed = domains.remove(domain.toLowerCase().trim());
        if (removed) persistToFile();
        return removed;
    }

    public boolean contains(String domain) {
        return domains.contains(domain.toLowerCase().trim());
    }
}
