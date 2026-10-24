package com.unipass.server;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

/**
 * Resolves the audit source address. Forwarding headers are only honored when
 * the direct peer is a registered load balancer, and the nearest untrusted hop
 * is used so a client cannot prepend a forged address. Only literal IP
 * addresses are accepted; no name resolution is performed on request data.
 */
final class TrustedProxy {
    private final List<Range> ranges;

    TrustedProxy(String configuration) {
        List<Range> parsed = new ArrayList<>();
        if (configuration != null) {
            for (String part : configuration.split(",")) {
                String value = part.trim();
                if (value.isEmpty()) continue;
                parsed.add(Range.parse(value));
            }
        }
        this.ranges = List.copyOf(parsed);
    }

    String resolve(HttpServletRequest request) {
        String peer = request.getRemoteAddr();
        if (peer == null || peer.isBlank()) return null;
        byte[] peerBytes = parse(peer);
        if (peerBytes == null || !trusted(peerBytes)) return canonical(peer);
        List<String> hops = hops(request);
        // Walk from the nearest proxy outwards; the first address that is not a
        // trusted proxy is the caller. Malformed entries stop the walk.
        for (int index = hops.size() - 1; index >= 0; index--) {
            String candidate = address(hops.get(index).trim());
            byte[] bytes = candidate == null ? null : parse(candidate);
            if (bytes == null) return canonical(peer);
            if (!trusted(bytes)) return canonical(candidate);
        }
        return canonical(peer);
    }

    private static List<String> hops(HttpServletRequest request) {
        List<String> values = new ArrayList<>();
        String forwarded = request.getHeader("Forwarded");
        if (forwarded != null) {
            for (String element : forwarded.split(",")) {
                for (String directive : element.split(";")) {
                    String[] pair = directive.trim().split("=", 2);
                    if (pair.length == 2 && pair[0].equalsIgnoreCase("for")) values.add(unquote(pair[1]));
                }
            }
            return values;
        }
        String header = request.getHeader("X-Forwarded-For");
        if (header != null) values.addAll(Arrays.asList(header.split(",")));
        return values;
    }

    private static String address(String value) {
        String result = value;
        if (result.startsWith("[")) {
            int close = result.indexOf(']');
            if (close < 0) return null;
            result = result.substring(1, close);
        } else if (result.indexOf(':') == result.lastIndexOf(':') && result.indexOf('.') > 0) {
            result = result.substring(0, result.indexOf(':'));
        }
        result = result.replaceAll("^\"|\"$", "");
        return result;
    }

    private boolean trusted(byte[] address) {
        for (Range range : ranges) if (range.contains(address)) return true;
        return false;
    }

    private static String unquote(String value) {
        String result = value.trim();
        if (result.length() >= 2 && result.startsWith("\"") && result.endsWith("\"")) result = result.substring(1, result.length() - 1);
        return result;
    }

    private static byte[] parse(String value) {
        if (value == null || value.length() > 64) return null;
        // Only IP literals are accepted so request data can never trigger name resolution.
        boolean ipv4 = value.matches("\\d{1,3}(\\.\\d{1,3}){3}");
        boolean ipv6 = value.indexOf(':') > 0 && value.matches("[0-9A-Fa-f:.]+");
        if (!ipv4 && !ipv6) return null;
        try { return InetAddress.getByName(value).getAddress(); }
        catch (UnknownHostException invalid) { return null; }
    }

    private static String canonical(String value) {
        byte[] bytes = parse(value);
        if (bytes == null) return value.length() > 64 ? value.substring(0, 64) : value;
        try { return InetAddress.getByAddress(bytes).getHostAddress(); }
        catch (UnknownHostException impossible) { return value; }
    }

    private record Range(byte[] network, int prefix) {
        static Range parse(String value) {
            int slash = value.indexOf('/');
            String host = slash < 0 ? value : value.substring(0, slash);
            byte[] address = TrustedProxy.parse(host);
            if (address == null) throw new IllegalArgumentException("Invalid trusted proxy address");
            int bits = address.length * 8;
            int prefix = bits;
            if (slash >= 0) {
                try { prefix = Integer.parseInt(value.substring(slash + 1)); }
                catch (NumberFormatException invalid) { throw new IllegalArgumentException("Invalid trusted proxy prefix"); }
                if (prefix < 0 || prefix > bits) throw new IllegalArgumentException("Invalid trusted proxy prefix");
            }
            return new Range(address, prefix);
        }
        boolean contains(byte[] address) {
            if (address.length != network.length) return false;
            int full = prefix / 8, remainder = prefix % 8;
            for (int index = 0; index < full; index++) if (address[index] != network[index]) return false;
            if (remainder == 0) return true;
            int mask = 0xFF << (8 - remainder);
            return (address[full] & mask) == (network[full] & mask);
        }
    }
}
