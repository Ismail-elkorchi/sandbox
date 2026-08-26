# Managed networking

Managed networking permits selected outbound TCP connections without giving the target a direct external route. The target communicates with namespace-local proxy and DNS listeners; a host-side broker resolves and authorizes every destination before connecting.

## Rules

```ts
network: {
  mode: "managed",
  allow: [
    {
      transport: "tcp",
      destination: {
        kind: "dns",
        name: "api.example.com",
        includeSubdomains: false,
      },
      ports: [443],
    },
    {
      transport: "tcp",
      destination: { kind: "ip", cidr: "203.0.113.0/24" },
      ports: [{ from: 8000, to: 8100 }],
    },
  ],
}
```

Rules are deny-by-default and transport-, destination-, and port-specific. Domain names are normalized with IDNA, lowercased, and stripped of one trailing dot. An exact-domain rule does not match siblings or subdomains unless `includeSubdomains` is true.

Private, loopback, link-local, multicast, unspecified, and host-only addresses are denied unless the matching rule explicitly authorizes the relevant private address space. Prefer narrow IP-prefix rules when private access is intentional.

## Supported target protocols

The initial broker supports:

- HTTP proxy requests with absolute URIs.
- HTTP `CONNECT` tunnels.
- SOCKS5 `CONNECT` using domain or IP destinations.
- Brokered DNS over UDP and TCP.

Proxy and resolver variables are placed in the target environment. Clients that ignore them still have no direct external route. UDP applications other than DNS, inbound exposure, ICMP, raw sockets, packet forwarding, TLS interception, and credential injection are not supported.

## DNS and rebinding

The broker resolves domain destinations itself. It validates every final address against the rule and private-address policy immediately before connection. A permitted name that resolves to any prohibited or unauthorized result is denied; clients cannot select an unchecked answer from a multi-answer response.

CNAME and resolver behavior are bounded by the host resolver. The rule remains attached to the original normalized destination, while all returned connection addresses are independently checked. DNS responses delivered to the target contain only authorized results.

## Violations and accounting

Denied attempts produce bounded structured violations with a policy kind, mechanism, process identity, timestamp, and sanitized destination metadata. Target stderr text is never parsed into a violation.

The final usage report includes accepted connection counts when available. Cancellation and cleanup close listeners and active broker streams; cleanup failures are retained in the result.

## Hardware VMs

The Firecracker guest has no virtual NIC in managed mode. A nonce-authenticated guest proxy transports requests over Virtio sockets to the same host policy broker, preserving the no-direct-route property.
