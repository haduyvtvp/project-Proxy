package vn.secureproxy.policy;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;

public class PolicyConfigCheck {

    public static void main(String[] args) throws Exception {
        String[] candidates = {
                args.length > 0 ? args[0] : "",
                "proxy/policy.sample.json",
                "policy.sample.json",
                "/data/policy.json"
        };

        File file = null;
        for (String c : candidates) {
            if (!c.isEmpty() && new File(c).isFile()) {
                file = new File(c);
                break;
            }
        }
        if (file == null) {
            System.err.println("Khong tim thay policy.sample.json");
            return;
        }

        PolicyConfig cfg = new ObjectMapper().readValue(file, PolicyConfig.class);

        System.out.println("File: " + file.getAbsolutePath());
        System.out.println("mode=" + cfg.mode() + ", timezone=" + cfg.timezone()
                + ", allow=" + cfg.allow().size());
        for (PolicyConfig.Category c : cfg.categories()) {
            System.out.println("- " + c.id() + " | " + c.name()
                    + " | active=" + c.active()
                    + " | patterns=" + c.patterns().size()
                    + " | schedule=" + c.schedule().size());
        }
    }
}