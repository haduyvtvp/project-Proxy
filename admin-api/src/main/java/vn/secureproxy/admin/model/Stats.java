package vn.secureproxy.admin.model;

import java.util.List;

public class Stats {
    private long total;
    private long allowed;
    private long blocked;
    private long error;
    private List<DomainCount> topBlocked;

    public Stats() {}

    public Stats(long total, long allowed, long blocked, long error, List<DomainCount> topBlocked) {
        this.total = total;
        this.allowed = allowed;
        this.blocked = blocked;
        this.error = error;
        this.topBlocked = topBlocked;
    }

    // -------- Getters & Setters --------

    public long getTotal() { return total; }
    public void setTotal(long total) { this.total = total; }

    public long getAllowed() { return allowed; }
    public void setAllowed(long allowed) { this.allowed = allowed; }

    public long getBlocked() { return blocked; }
    public void setBlocked(long blocked) { this.blocked = blocked; }

    public long getError() { return error; }
    public void setError(long error) { this.error = error; }

    public List<DomainCount> getTopBlocked() { return topBlocked; }
    public void setTopBlocked(List<DomainCount> topBlocked) { this.topBlocked = topBlocked; }

    /** Simple DTO: { "domain": "facebook.com", "count": 5 } */
    public static class DomainCount {
        private String domain;
        private long count;

        public DomainCount() {}

        public DomainCount(String domain, long count) {
            this.domain = domain;
            this.count = count;
        }

        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }

        public long getCount() { return count; }
        public void setCount(long count) { this.count = count; }
    }
}
