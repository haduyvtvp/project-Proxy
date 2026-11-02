package vn.secureproxy.policy;

/** Ket qua danh gia: cho phep hay chan, kem ly do (dung de ghi log). */
public record Decision(boolean allowed, String reason) {

    public static Decision allow(String reason) {
        return new Decision(true, reason);
    }

    public static Decision block(String reason) {
        return new Decision(false, reason);
    }
}