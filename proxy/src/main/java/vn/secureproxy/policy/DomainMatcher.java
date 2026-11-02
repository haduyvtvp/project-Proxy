package vn.secureproxy.policy;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * So khop ten mien voi danh sach mau:
 *   "facebook.com"   -> khop facebook.com va moi ten mien phu (a.facebook.com)
 *   "*.fbcdn.net"    -> chi khop ten mien phu, KHONG khop fbcdn.net
 *   "regex:<bieu thuc>" -> khop theo bieu thuc chinh quy tren ten mien
 * Host phai duoc chuan hoa (chu thuong, bo cong) truoc khi truyen vao.
 */
public class DomainMatcher {

    private final Set<String> suffixes = new HashSet<>();
    private final Set<String> subdomainOnly = new HashSet<>();
    private final List<Pattern> regexes = new ArrayList<>();

    public DomainMatcher(Collection<String> patterns) {
        if (patterns == null) {
            return;
        }

        for (String raw : patterns) {
            if (raw == null) {
                continue;
            }

            String p = raw.trim();
            if (p.isEmpty() || p.startsWith("#")) {
                continue;
            }

            if (p.regionMatches(true, 0, "regex:", 0, 6)) {
                String expr = p.substring(6).trim();
                try {
                    regexes.add(Pattern.compile(expr, Pattern.CASE_INSENSITIVE));
                } catch (PatternSyntaxException e) {
                    System.err.println("[DomainMatcher] Bo qua regex loi: "
                            + expr + " - " + e.getDescription());
                }
            } else if (p.startsWith("*.")) {
                String d = normalize(p.substring(2));
                if (!d.isEmpty()) {
                    subdomainOnly.add(d);
                }
            } else {
                String d = normalize(p);
                if (!d.isEmpty()) {
                    suffixes.add(d);
                }
            }
        }
    }

    private static String normalize(String s) {
        String d = s.trim().toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        return d;
    }

    public boolean matches(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }

        if (suffixes.contains(host)) {
            return true;
        }

        // Duyet tung cap cha: a.b.com -> b.com -> com
        String rest = host;
        int dot;
        while ((dot = rest.indexOf('.')) >= 0) {
            rest = rest.substring(dot + 1);
            if (rest.isEmpty()) {
                break;
            }
            if (suffixes.contains(rest) || subdomainOnly.contains(rest)) {
                return true;
            }
        }

        for (Pattern p : regexes) {
            if (p.matcher(host).find()) {
                return true;
            }
        }

        return false;
    }
}