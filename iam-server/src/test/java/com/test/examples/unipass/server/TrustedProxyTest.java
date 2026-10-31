package com.test.examples.unipass.server;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class TrustedProxyTest {
  private static MockHttpServletRequest request(String peer, String xff, String forwarded) {
    var request = new MockHttpServletRequest("POST", "/api/admin/console/audit");
    request.setRemoteAddr(peer);
    if (xff != null) request.addHeader("X-Forwarded-For", xff);
    if (forwarded != null) request.addHeader("Forwarded", forwarded);
    return request;
  }

  @Test
  void ignoresForwardingHeadersFromUntrustedPeers() {
    var proxy = new TrustedProxy("10.0.0.0/8");
    assertEquals("198.51.100.7", proxy.resolve(request("198.51.100.7", "203.0.113.9", null)));
    assertEquals("198.51.100.7", proxy.resolve(request("198.51.100.7", null, "for=203.0.113.9")));
  }

  @Test
  void usesTheNearestUntrustedHopAndIgnoresClientPrependedValues() {
    var proxy = new TrustedProxy("10.0.0.0/8, 192.168.0.0/16");
    assertEquals(
        "198.51.100.7",
        proxy.resolve(request("10.1.2.3", "203.0.113.5, 198.51.100.7, 10.9.9.9", null)));
    assertEquals(
        "198.51.100.8", proxy.resolve(request("10.0.0.1", "198.51.100.8, 192.168.5.5", null)));
    // Every hop is a registered proxy: fall back to the direct peer.
    assertEquals("10.1.2.3", proxy.resolve(request("10.1.2.3", "10.8.8.8, 192.168.5.5", null)));
  }

  @Test
  void stripsPortsAndHandlesQuotedForwardedElements() {
    var proxy = new TrustedProxy("10.0.0.0/8");
    assertEquals("198.51.100.7", proxy.resolve(request("10.0.0.1", "198.51.100.7:44321", null)));
    assertEquals(
        "198.51.100.7",
        proxy.resolve(request("10.0.0.1", null, "for=\"198.51.100.7:443\";proto=https")));
    String v6 = proxy.resolve(request("10.0.0.1", null, "for=\"[2001:db8::1]:443\""));
    assertNotNull(v6);
    assertTrue(v6.contains("2001:db8"), v6);
  }

  @Test
  void malformedHopsFallBackToThePeerRatherThanTrustingInput() {
    var proxy = new TrustedProxy("10.0.0.0/8");
    assertEquals("10.0.0.1", proxy.resolve(request("10.0.0.1", "not-an-ip", null)));
    assertEquals(
        "10.0.0.1", proxy.resolve(request("10.0.0.1", "198.51.100.7, evil.example", null)));
    assertEquals("10.0.0.1", proxy.resolve(request("10.0.0.1", "", null)));
  }

  @Test
  void supportsIpv6RangesAndRejectsInvalidConfiguration() {
    var proxy = new TrustedProxy("2001:db8::/32");
    String result = proxy.resolve(request("2001:db8::5", "198.51.100.9", null));
    assertEquals("198.51.100.9", result);
    assertEquals(
        "198.51.100.9", new TrustedProxy("").resolve(request("198.51.100.9", "10.0.0.1", null)));
    assertThrows(IllegalArgumentException.class, () -> new TrustedProxy("not-an-address"));
    assertThrows(IllegalArgumentException.class, () -> new TrustedProxy("10.0.0.0/33"));
    assertThrows(IllegalArgumentException.class, () -> new TrustedProxy("10.0.0.0/x"));
  }
}
