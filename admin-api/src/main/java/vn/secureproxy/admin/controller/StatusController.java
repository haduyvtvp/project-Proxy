package vn.secureproxy.admin.controller;

import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/status")
public class StatusController {

    @GetMapping
    public Map<String, String> getStatus() {
        return Map.of("status", "running", "service", "secure-proxy-admin");
    }
}
