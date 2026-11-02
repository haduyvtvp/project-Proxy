package vn.secureproxy.admin.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import vn.secureproxy.admin.model.PolicyDocument;
import vn.secureproxy.admin.model.PolicyDocument.Category;
import vn.secureproxy.admin.model.PolicyDocument.Schedule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyManagementServiceTest {

    @TempDir
    Path directory;

    private PolicyManagementService service() {
        return new PolicyManagementService(
                directory.resolve("policy.json"),
                new ObjectMapper()
        );
    }

    @Test
    void savesAndReadsPolicyWithPatternsAndSchedules() {
        PolicyDocument expected = new PolicyDocument(
                "whitelist",
                "Asia/Ho_Chi_Minh",
                List.of("wikipedia.org", "*.trusted.example"),
                List.of(new Category(
                        "games",
                        "Games",
                        true,
                        List.of("game.example", "*.cdn.example", "regex:^play[0-9]+\\.example$"),
                        List.of(new Schedule(List.of("MON", "FRI"), "22:00", "06:00"))
                ))
        );

        service().savePolicy(expected);

        PolicyDocument saved = service().getPolicy();
        assertEquals("WHITELIST", saved.mode());
        assertEquals(expected.timezone(), saved.timezone());
        assertEquals(expected.allow(), saved.allow());
        assertEquals(expected.categories(), saved.categories());
    }

    @Test
    void rejectsInvalidRegexWithoutReplacingCurrentPolicy() throws Exception {
        PolicyManagementService service = service();
        PolicyDocument valid = new PolicyDocument("BLOCKLIST", "UTC", List.of(), List.of());
        service.savePolicy(valid);
        String originalFile = Files.readString(directory.resolve("policy.json"));

        PolicyDocument invalid = new PolicyDocument(
                "BLOCKLIST",
                "UTC",
                List.of(),
                List.of(new Category("broken", "Broken", true, List.of("regex:["), List.of()))
        );

        assertThrows(IllegalArgumentException.class, () -> service.savePolicy(invalid));
        assertEquals(originalFile, Files.readString(directory.resolve("policy.json")));
        try (var files = Files.list(directory)) {
            assertTrue(files.noneMatch(path -> path.getFileName().toString().endsWith(".tmp")));
        }
    }

    @Test
    void rejectsInvalidScheduleDayAndTimezone() {
        PolicyDocument invalidSchedule = new PolicyDocument(
                "BLOCKLIST",
                "UTC",
                List.of(),
                List.of(new Category(
                        "games",
                        "Games",
                        true,
                        List.of("game.example"),
                        List.of(new Schedule(List.of("FUNDAY"), "09:00", "17:00"))
                ))
        );
        assertThrows(IllegalArgumentException.class, () -> service().savePolicy(invalidSchedule));

        PolicyDocument invalidTimezone = new PolicyDocument("WHITELIST", "Mars/Olympus", List.of(), List.of());
        assertThrows(IllegalArgumentException.class, () -> service().savePolicy(invalidTimezone));

        PolicyDocument invalidWildcard = new PolicyDocument(
                "BLOCKLIST",
                "UTC",
                List.of(),
                List.of(new Category("wildcard", "Wildcard", true, List.of("*.*.example.com"), List.of()))
        );
        assertThrows(IllegalArgumentException.class, () -> service().savePolicy(invalidWildcard));
    }
}
