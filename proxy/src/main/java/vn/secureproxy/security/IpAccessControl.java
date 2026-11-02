package vn.secureproxy.security;

import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;

public final class IpAccessControl {

    public static final String DEFAULT_CIDRS =
            "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7";

    private final List<IpNetwork> allowedNetworks;

    public IpAccessControl(String cidrs) {
        if (cidrs == null || cidrs.isBlank()) {
            throw new IllegalArgumentException("Allowed proxy CIDRs must not be empty");
        }
        this.allowedNetworks = Arrays.stream(cidrs.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .map(IpNetwork::parse)
                .toList();
        if (allowedNetworks.isEmpty()) {
            throw new IllegalArgumentException("At least one proxy CIDR must be configured");
        }
    }

    public boolean isAllowed(InetAddress address) {
        return address != null && allowedNetworks.stream().anyMatch(network -> network.contains(address));
    }
}
