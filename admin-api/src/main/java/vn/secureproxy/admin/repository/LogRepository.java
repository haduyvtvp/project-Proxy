package vn.secureproxy.admin.repository;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;
import vn.secureproxy.admin.model.LogEntry;
import vn.secureproxy.admin.model.LogPage;
import vn.secureproxy.admin.model.MonitoringSnapshot;
import vn.secureproxy.admin.model.MonitoringSnapshot.RankedValue;
import vn.secureproxy.admin.model.MonitoringSnapshot.TimeBucket;

import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

@Repository
public class LogRepository {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final String INSERT =
            "INSERT INTO access_logs (logged_at, client, host, method, result, reason, raw) " +
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (raw) DO NOTHING";

    private static final RowMapper<LogEntry> LOG_ENTRY_ROW_MAPPER = (rs, rowNum) -> {
        Timestamp timestamp = rs.getTimestamp("logged_at");
        return new LogEntry(
                timestamp.toLocalDateTime().format(TIMESTAMP_FORMAT),
                rs.getString("client"),
                rs.getString("host"),
                rs.getString("method"),
                rs.getString("result"),
                rs.getString("reason"),
                rs.getString("raw")
        );
    };

    private final JdbcTemplate jdbc;

    public LogRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Ghi 1 dong log; dong trung (cung raw) se bi bo qua. */
    public void save(LogEntry e) {
        jdbc.update(INSERT, ps -> fill(ps, e));
    }

    /** Ghi nhieu dong cung luc (dung khi nhap log cu). */
    public void saveAll(List<LogEntry> entries) {
        if (entries.isEmpty()) {
            return;
        }
        jdbc.batchUpdate(INSERT, entries, 500, (ps, e) -> fill(ps, e));
    }

    public long count() {
        Long n = jdbc.queryForObject("SELECT COUNT(*) FROM access_logs", Long.class);
        return n == null ? 0 : n;
    }

    public List<LogEntry> findRecent(int limit) {
        if (limit <= 0) {
            return List.of();
        }

        List<LogEntry> entries = jdbc.query(
                "SELECT logged_at, client, host, method, result, reason, raw " +
                        "FROM access_logs ORDER BY logged_at DESC, id DESC LIMIT ?",
                LOG_ENTRY_ROW_MAPPER,
                limit
        );
        List<LogEntry> chronological = new ArrayList<>(entries);
        java.util.Collections.reverse(chronological);
        return chronological;
    }

    public List<LogEntry> findAll() {
        return jdbc.query(
                "SELECT logged_at, client, host, method, result, reason, raw " +
                        "FROM access_logs ORDER BY logged_at, id",
                LOG_ENTRY_ROW_MAPPER
        );
    }

    public MonitoringSnapshot findMonitoring(
            LocalDateTime from,
            LocalDateTime to,
            int bucketMinutes
    ) {
        long[] totals = jdbc.queryForObject(
                "SELECT COUNT(*), " +
                        "COUNT(*) FILTER (WHERE result = 'ALLOWED'), " +
                        "COUNT(*) FILTER (WHERE result = 'BLOCKED'), " +
                        "COUNT(*) FILTER (WHERE result = 'ERROR') " +
                        "FROM access_logs WHERE logged_at >= ? AND logged_at < ?",
                (rs, rowNum) -> new long[]{
                        rs.getLong(1), rs.getLong(2), rs.getLong(3), rs.getLong(4)
                },
                Timestamp.valueOf(from),
                Timestamp.valueOf(to)
        );

        List<TimeBucket> timeline = jdbc.query(
                "SELECT to_timestamp(floor(extract(epoch FROM logged_at) / (? * 60)) * (? * 60)) " +
                        "AT TIME ZONE 'UTC' AS bucket, " +
                        "COUNT(*) AS total, " +
                        "COUNT(*) FILTER (WHERE result = 'ALLOWED') AS allowed, " +
                        "COUNT(*) FILTER (WHERE result = 'BLOCKED') AS blocked " +
                        "FROM access_logs WHERE logged_at >= ? AND logged_at < ? " +
                        "GROUP BY bucket ORDER BY bucket",
                (rs, rowNum) -> new TimeBucket(
                        rs.getTimestamp("bucket").toLocalDateTime(),
                        rs.getLong("total"),
                        rs.getLong("allowed"),
                        rs.getLong("blocked")
                ),
                bucketMinutes,
                bucketMinutes,
                Timestamp.valueOf(from),
                Timestamp.valueOf(to)
        );

        List<RankedValue> topDomains = jdbc.query(
                "SELECT host AS value, COUNT(*) AS count FROM access_logs " +
                        "WHERE logged_at >= ? AND logged_at < ? AND host IS NOT NULL AND host <> '' " +
                        "GROUP BY host ORDER BY count DESC, host LIMIT 10",
                (rs, rowNum) -> new RankedValue(rs.getString("value"), rs.getLong("count")),
                Timestamp.valueOf(from),
                Timestamp.valueOf(to)
        );

        List<RankedValue> topClients = jdbc.query(
                "WITH parsed_clients AS (" +
                        "SELECT CASE WHEN client LIKE '/[%]:%' " +
                        "THEN substring(client FROM 3 FOR position(']' IN client) - 3) " +
                        "ELSE split_part(ltrim(client, '/'), ':', 1) END AS value " +
                        "FROM access_logs WHERE logged_at >= ? AND logged_at < ? " +
                        "AND client IS NOT NULL AND client <> ''" +
                        ") SELECT value, COUNT(*) AS count FROM parsed_clients " +
                        "WHERE value <> '' GROUP BY value ORDER BY count DESC, value LIMIT 10",
                (rs, rowNum) -> new RankedValue(rs.getString("value"), rs.getLong("count")),
                Timestamp.valueOf(from),
                Timestamp.valueOf(to)
        );

        return new MonitoringSnapshot(
                from, to, totals[0], totals[1], totals[2], totals[3],
                timeline, topDomains, topClients
        );
    }

    public LogPage findFiltered(
            LocalDateTime from,
            LocalDateTime to,
            String client,
            String host,
            int page,
            int size
    ) {
        String filters = "FROM access_logs WHERE logged_at >= ? AND logged_at < ? " +
                "AND (? = '' OR position(lower(?) in lower(COALESCE(client, ''))) > 0) " +
                "AND (? = '' OR position(lower(?) in lower(COALESCE(host, ''))) > 0)";
        Object[] filterArguments = {
                Timestamp.valueOf(from),
                Timestamp.valueOf(to),
                client, client,
                host, host
        };
        Long total = jdbc.queryForObject(
                "SELECT COUNT(*) " + filters,
                Long.class,
                filterArguments
        );
        List<LogEntry> entries = jdbc.query(
                "SELECT logged_at, client, host, method, result, reason, raw " + filters +
                        " ORDER BY logged_at DESC, id DESC LIMIT ? OFFSET ?",
                LOG_ENTRY_ROW_MAPPER,
                concat(filterArguments, size, (long) page * size)
        );
        return new LogPage(entries, page, size, total == null ? 0 : total);
    }

    private static Object[] concat(Object[] values, Object... extra) {
        Object[] result = java.util.Arrays.copyOf(values, values.length + extra.length);
        System.arraycopy(extra, 0, result, values.length, extra.length);
        return result;
    }

    private static void fill(PreparedStatement ps, LogEntry e) throws SQLException {
        ps.setTimestamp(1, Timestamp.valueOf(e.getTimestamp()));
        ps.setString(2, cut(e.getClient(), 100));
        ps.setString(3, cut(e.getHost(), 255));
        ps.setString(4, cut(e.getMethod(), 20));
        ps.setString(5, cut(e.getResult(), 20));
        ps.setString(6, cut(e.getReason(), 100));
        ps.setString(7, e.getRaw());
    }

    private static String cut(String s, int max) {
        if (s == null) {
            return null;
        }
        return s.length() <= max ? s : s.substring(0, max);
    }
}