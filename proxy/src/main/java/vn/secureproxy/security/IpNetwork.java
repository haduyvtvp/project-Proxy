package vn.secureproxy.security;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

public final class IpNetwork {

    private final byte[] network;
    private final int prefixLength;

    private IpNetwork(byte[] address, int prefixLength) {
        this.network = address.clone();
        this.prefixLength = prefixLength;
        mask(network, prefixLength);
    }

    public static IpNetwork parse(String value) {
        String cidr = value.trim();
        String[] parts = cidr.split("/", -1);
        if (parts.length > 2 || parts[0].isBlank()
                || !parts[0].matches("[0-9a-fA-F:.]+")) {
            throw new IllegalArgumentException("Invalid numeric IP network: " + value);
        }

        try {
            byte[] address = InetAddress.getByName(parts[0]).getAddress();
            int maxPrefix = address.length * 8;
            int prefix = parts.length == 1 ? maxPrefix : Integer.parseInt(parts[1]);
            if (prefix < 0 || prefix > maxPrefix) {
                throw new IllegalArgumentException("Invalid network prefix: " + value);
            }
            return new IpNetwork(address, prefix);
        } catch (UnknownHostException | NumberFormatException e) {
            throw new IllegalArgumentException("Invalid numeric IP network: " + value, e);
        }
    }

    public boolean contains(InetAddress address) {
        byte[] candidate = address.getAddress();
        if (candidate.length != network.length) {
            if (candidate.length == 16 && isIpv4Mapped(candidate)) {
                candidate = Arrays.copyOfRange(candidate, 12, 16);
            } else if (network.length == 16 && isIpv4Mapped(network)) {
                byte[] mapped = new byte[16];
                mapped[10] = (byte) 0xff;
                mapped[11] = (byte) 0xff;
                System.arraycopy(candidate, 0, mapped, 12, candidate.length);
                candidate = mapped;
            } else {
                return false;
            }
        }

        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        for (int i = 0; i < fullBytes; i++) {
            if (candidate[i] != network[i]) {
                return false;
            }
        }
        if (remainingBits == 0) {
            return true;
        }
        int mask = 0xff << (8 - remainingBits);
        return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
    }

    private static void mask(byte[] address, int prefixLength) {
        int fullBytes = prefixLength / 8;
        int remainingBits = prefixLength % 8;
        if (remainingBits > 0) {
            address[fullBytes] &= (byte) (0xff << (8 - remainingBits));
            fullBytes++;
        }
        Arrays.fill(address, fullBytes, address.length, (byte) 0);
    }

    private static boolean isIpv4Mapped(byte[] address) {
        if (address.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (address[i] != 0) {
                return false;
            }
        }
        return address[10] == (byte) 0xff && address[11] == (byte) 0xff;
    }
}
