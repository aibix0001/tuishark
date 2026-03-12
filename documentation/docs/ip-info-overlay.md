---
title: IP Address Info Overlay
date: 2026-03-12
author: Claude Opus 4.6
status: implemented
related_issues:
  - "#24"
related_mrs: []
---

## Overview

The IP Address Info overlay provides real-time lookup of ASN, AS name, country, and RIR allocation for IPv4/IPv6 addresses in captured packets. It is accessible via the `i` keybinding from any pane.

## Usage

1. Select a packet in the packet table
2. Press `i` to open the IP info dialog
3. View source and destination IP information side by side
4. Use `ö`/`ä` to navigate between packets while the dialog stays open
5. Press `Esc`, `q`, or `i` to close

## Information Displayed

### Public IPs

For routable public addresses, the overlay queries the BGPView API and displays:

- **ASN**: Autonomous System Number (e.g., AS13335)
- **AS Name**: Organization name (e.g., Cloudflare, Inc.)
- **Country**: Country code (e.g., US)
- **RIR**: Regional Internet Registry (e.g., APNIC, RIPE)

### Private/Special IPs

For private and special-use addresses, the overlay shows RFC information:

- **ASN**: RFC number (e.g., RFC1918)
- **AS Name**: RFC title (e.g., Address Allocation for Private Internets)
- **Country/RIR**: N/A

Recognized special ranges include RFC1918 (private), RFC6598 (CGNAT), RFC1122 (loopback), RFC3927 (link-local), RFC5737 (documentation), RFC4193 (IPv6 ULA), RFC4291 (IPv6 link-local/multicast), and others.

### Non-IP Packets

For packets without IP addresses (e.g., ARP), the dialog shows "No IP addresses in this packet".

## Architecture

### Background Lookups

API calls are non-blocking. When a public IP needs lookup:

1. The dialog opens immediately showing "Looking up..." for pending IPs
2. A background `std::thread` queries BGPView
3. Results are received via `mpsc::channel` and displayed on the next frame

### Caching

All lookup results are cached in an in-memory `HashMap<String, IpInfo>`. Subsequent lookups for the same IP are instant, including when navigating back to a previously viewed packet.

### Graceful Degradation

If the BGPView API is unreachable (network down, timeout), the dialog shows "Lookup failed" with the IP address still visible. The 5-second timeout prevents the background thread from hanging indefinitely.

## Configuration

The keybinding is configurable in `~/.config/tuishark/config.toml`:

```toml
[keys]
ip_info = "i"
```
