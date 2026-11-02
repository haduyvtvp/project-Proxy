package vn.secureproxy.admin.model;

public class LogEntry {
    private String timestamp;
    private String client;
    private String host;
    private String method;
    private String result;
    private String raw;

    public LogEntry() {}

    public LogEntry(String timestamp, String client, String host, String method, String result, String raw) {
        this.timestamp = timestamp;
        this.client = client;
        this.host = host;
        this.method = method;
        this.result = result;
        this.raw = raw;
    }

    // -------- Getters & Setters --------

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getClient() { return client; }
    public void setClient(String client) { this.client = client; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public String getMethod() { return method; }
    public void setMethod(String method) { this.method = method; }

    public String getResult() { return result; }
    public void setResult(String result) { this.result = result; }

    public String getRaw() { return raw; }
    public void setRaw(String raw) { this.raw = raw; }
}
