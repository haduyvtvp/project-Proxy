package vn.secureproxy.admin.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.secureproxy.admin.service.BlocklistService;

import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/blocklist")
public class BlocklistController {

    private final BlocklistService blocklistService;

    public BlocklistController(BlocklistService blocklistService) {
        this.blocklistService = blocklistService;
    }

    @GetMapping
    public Set<String> getBlocklist() {
        return blocklistService.getDomains();
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> addDomain(@RequestBody Map<String, String> body) {
        String domain = body.get("domain");
        if (domain == null || domain.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("success", false, "message", "Domain is required"));
        }
        boolean added = blocklistService.addDomain(domain.trim());
        if (added) {
            return ResponseEntity.ok(Map.of("success", true, "message", "Domain added: " + domain.trim()));
        } else {
            return ResponseEntity.ok(Map.of("success", false, "message", "Domain already exists: " + domain.trim()));
        }
    }

    @DeleteMapping("/{domain}")
    public ResponseEntity<Map<String, Object>> removeDomain(@PathVariable String domain) {
        boolean removed = blocklistService.removeDomain(domain);
        if (removed) {
            return ResponseEntity.ok(Map.of("success", true, "message", "Domain removed: " + domain));
        } else {
            return ResponseEntity.status(404).body(Map.of("success", false, "message", "Domain not found: " + domain));
        }
    }
}
