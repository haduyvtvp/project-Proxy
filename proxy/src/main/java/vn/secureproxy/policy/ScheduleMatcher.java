package vn.secureproxy.policy;

import java.time.DayOfWeek;
import java.time.LocalTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Kiem tra thoi diem hien tai co nam trong khung gio nao do khong.
 * - days rong = moi ngay
 * - from/to dinh dang "HH:mm" (vi du 07:30)
 * - from > to = khung qua nua dem (vi du 22:00 -> 06:00)
 * - from == to (hoac khong ghi) = ca ngay
 */
public class ScheduleMatcher {

    private record Entry(Set<DayOfWeek> days, LocalTime from, LocalTime to) {
    }

    private final List<Entry> entries = new ArrayList<>();

    public ScheduleMatcher(List<PolicyConfig.Schedule> schedules) {
        for (PolicyConfig.Schedule s : schedules) {
            try {
                entries.add(compile(s));
            } catch (RuntimeException e) {
                System.err.println("[ScheduleMatcher] Bo qua khung gio loi ("
                        + s + "): " + e.getMessage());
            }
        }
    }

    private static Entry compile(PolicyConfig.Schedule s) {
        Set<DayOfWeek> days = EnumSet.noneOf(DayOfWeek.class);
        for (String d : s.days()) {
            days.add(parseDay(d));
        }
        if (days.isEmpty()) {
            days = EnumSet.allOf(DayOfWeek.class);
        }

        LocalTime from = (s.from() == null || s.from().isBlank())
                ? LocalTime.MIN : LocalTime.parse(s.from().trim());
        LocalTime to = (s.to() == null || s.to().isBlank())
                ? LocalTime.MIN : LocalTime.parse(s.to().trim());

        return new Entry(days, from, to);
    }

    private static DayOfWeek parseDay(String s) {
        String k = s.trim().toUpperCase(Locale.ROOT);
        if (k.length() >= 3) {
            k = k.substring(0, 3);
        }
        return switch (k) {
            case "MON" -> DayOfWeek.MONDAY;
            case "TUE" -> DayOfWeek.TUESDAY;
            case "WED" -> DayOfWeek.WEDNESDAY;
            case "THU" -> DayOfWeek.THURSDAY;
            case "FRI" -> DayOfWeek.FRIDAY;
            case "SAT" -> DayOfWeek.SATURDAY;
            case "SUN" -> DayOfWeek.SUNDAY;
            default -> throw new IllegalArgumentException("Ngay khong hop le: " + s);
        };
    }

    public boolean matches(ZonedDateTime now) {
        DayOfWeek today = now.getDayOfWeek();
        LocalTime t = now.toLocalTime();

        for (Entry e : entries) {
            if (e.from().equals(e.to())) {
                if (e.days().contains(today)) {
                    return true;
                }
            } else if (e.from().isBefore(e.to())) {
                if (e.days().contains(today)
                        && !t.isBefore(e.from()) && t.isBefore(e.to())) {
                    return true;
                }
            } else {
                // Khung qua nua dem: phan truoc 24:00 tinh theo hom nay,
                // phan sau 00:00 tinh theo ngay bat dau (hom qua)
                if (e.days().contains(today) && !t.isBefore(e.from())) {
                    return true;
                }
                if (e.days().contains(today.minus(1)) && t.isBefore(e.to())) {
                    return true;
                }
            }
        }

        return false;
    }
}