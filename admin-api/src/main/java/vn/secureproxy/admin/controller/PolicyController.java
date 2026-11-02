package vn.secureproxy.admin.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import vn.secureproxy.admin.model.PolicyDocument;
import vn.secureproxy.admin.service.PolicyManagementService;

import java.util.Map;

@RestController
@RequestMapping("/api/policy")
public class PolicyController {

    private final PolicyManagementService policyService;

    public PolicyController(PolicyManagementService policyService) {
        this.policyService = policyService;
    }

    @GetMapping
    public PolicyDocument getPolicy() {
        return policyService.getPolicy();
    }

    @PutMapping
    public PolicyDocument savePolicy(@RequestBody PolicyDocument policy) {
        return policyService.savePolicy(policy);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, String>> handleInvalidPolicy(IllegalArgumentException e) {
        return ResponseEntity.badRequest().body(Map.of("message", e.getMessage()));
    }
}
