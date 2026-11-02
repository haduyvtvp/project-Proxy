package vn.secureproxy.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import vn.secureproxy.admin.model.PolicyDocument;
import vn.secureproxy.admin.model.PolicyDocument.Category;
import vn.secureproxy.admin.model.PolicyDocument.Schedule;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.DateTimeException;
import java.time.LocalTime;
import java.time.ZoneId;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Service
public class PolicyManagementService {

    private static final Set<String> DAYS =
            Set.of("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN");
    private static final Pattern CATEGORY_ID = Pattern.compile("[a-zA-Z0-9_-]+");
    private static final Pattern TIME = Pattern.compile("\\d{2}:\\d{2}");
    private static final int MAX_PATTERN_LENGTH = 512;

    private final Path policyFile;
    private final ObjectMapper objectMapper;

    @Autowired
    public PolicyManagementService(
            @Value("${secureproxy.data-dir:/data}") String dataDirectory,
            ObjectMapper objectMapper
    ) {
        this(Path.of(dataDirectory).resolve("policy.json"), objectMapper);
    }

    PolicyManagementService(Path policyFile, ObjectMapper objectMapper) {
        this.policyFile = policyFile;
        this.objectMapper = objectMapper;
    }

    public PolicyDocument getPolicy() {
        if (!Files.isRegularFile(policyFile)) {
            return new PolicyDocument("BLOCKLIST", "Asia/Ho_Chi_Minh", List.of(), List.of());
        }
        try {
            return objectMapper.readValue(policyFile.toFile(), PolicyDocument.class);
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot read policy configuration", e);
        }
    }

    public PolicyDocument savePolicy(PolicyDocument policy) {
        PolicyDocument normalized = validateAndNormalize(policy);
        Path parent = policyFile.toAbsolutePath().getParent();
        Path temporaryFile = null;
        try {
            Files.createDirectories(parent);
            temporaryFile = Files.createTempFile(parent, "policy-", ".json.tmp");
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(temporaryFile.toFile(), normalized);
            try {
                Files.move(temporaryFile, policyFile,
                        StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporaryFile, policyFile, StandardCopyOption.REPLACE_EXISTING);
            }
            return normalized;
        } catch (IOException e) {
            if (temporaryFile != null) {
                try {
                    Files.deleteIfExists(temporaryFile);
                } catch (IOException cleanupError) {
                    e.addSuppressed(cleanupError);
                }
            }
            throw new UncheckedIOException("Cannot save policy configuration", e);
        }
    }

    private static PolicyDocument validateAndNormalize(PolicyDocument policy) {
        if (policy == null) {
            throw new IllegalArgumentException("Policy body is required");
        }

        String mode = required(policy.mode(), "mode").toUpperCase(Locale.ROOT);
        if (!mode.equals("BLOCKLIST") && !mode.equals("WHITELIST")) {
            throw new IllegalArgumentException("mode must be BLOCKLIST or WHITELIST");
        }

        String timezone = required(policy.timezone(), "timezone");
        try {
            ZoneId.of(timezone);
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("timezone must be a valid IANA timezone", e);
        }

        List<String> allow = policy.allow() == null ? List.of() : policy.allow().stream()
                .map(pattern -> validatePattern(pattern, "allow"))
                .toList();
        List<Category> categories = policy.categories() == null
                ? List.of() : validateCategories(policy.categories());

        return new PolicyDocument(mode, timezone, allow, categories);
    }

    private static List<Category> validateCategories(List<Category> categories) {
        Set<String> ids = new HashSet<>();
        return categories.stream().map(category -> {
            if (category == null) {
                throw new IllegalArgumentException("categories cannot contain null");
            }
            String id = required(category.id(), "category id");
            if (!CATEGORY_ID.matcher(id).matches() || !ids.add(id)) {
                throw new IllegalArgumentException(
                        "category ids must be unique and contain only letters, numbers, _ or -");
            }
            String name = required(category.name(), "category name");
            List<String> patterns = category.patterns() == null ? List.of()
                    : category.patterns().stream()
                            .map(pattern -> validatePattern(pattern, "category " + id))
                            .toList();
            List<Schedule> schedules = category.schedule() == null ? List.of()
                    : category.schedule().stream()
                            .map(schedule -> validateSchedule(schedule, id))
                            .toList();
            return new Category(id, name, category.enabled(), patterns, schedules);
        }).toList();
    }

    private static Schedule validateSchedule(Schedule schedule, String categoryId) {
        if (schedule == null) {
            throw new IllegalArgumentException("category " + categoryId + " has an empty schedule");
        }

        List<String> days = schedule.days() == null ? List.of() : schedule.days().stream()
                .map(day -> required(day, "schedule day").toUpperCase(Locale.ROOT))
                .peek(day -> {
                    if (!DAYS.contains(day)) {
                        throw new IllegalArgumentException("invalid schedule day: " + day);
                    }
                })
                .distinct()
                .toList();
        String from = normalizeTime(schedule.from(), "schedule from");
        String to = normalizeTime(schedule.to(), "schedule to");
        return new Schedule(days, from, to);
    }

    private static String normalizeTime(String value, String field) {
        if (value == null || value.isBlank()) {
            return "00:00";
        }
        String time = value.trim();
        if (!TIME.matcher(time).matches()) {
            throw new IllegalArgumentException(field + " must use HH:mm");
        }
        try {
            LocalTime.parse(time);
        } catch (DateTimeException e) {
            throw new IllegalArgumentException(field + " is not a valid time", e);
        }
        return time;
    }

    private static String validatePattern(String raw, String owner) {
        String pattern = required(raw, owner + " pattern");
        if (pattern.length() > MAX_PATTERN_LENGTH || pattern.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException(owner + " patterns must be at most 512 characters with no spaces");
        }

        if (pattern.regionMatches(true, 0, "regex:", 0, 6)) {
            String expression = pattern.substring(6);
            if (expression.isBlank()) {
                throw new IllegalArgumentException(owner + " regex cannot be empty");
            }
            try {
                Pattern.compile(expression, Pattern.CASE_INSENSITIVE);
            } catch (PatternSyntaxException e) {
                throw new IllegalArgumentException(owner + " has an invalid regex: " + e.getDescription(), e);
            }
        } else if (pattern.startsWith("*.")) {
            String domain = pattern.substring(2);
            if (domain.isBlank() || domain.contains("*")) {
                throw new IllegalArgumentException("wildcards must use the form *.example.com");
            }
        } else if (pattern.contains("*")) {
            throw new IllegalArgumentException("wildcards must use the form *.example.com");
        }
        return pattern;
    }

    private static String required(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }
}
