---
title: "LinkMeta Surface: pflog/enc in Packet Table, Filters & Export"
date: 2026-03-14
author: agent
status: active
related_issues: [33]
related_mrs: [36]
---

## Overview

Phase 10 added pflog and enc link-layer parsing, populating `PacketSummary.link_meta` with pflog action/direction/interface/rule/reason and enc SPI/flags. However, this metadata was only rendered in the detail tree — the packet table, display filter engine, and export modules could not access it.

This change surfaces `LinkMeta` across the full UI and export pipeline, enabling FreeBSD/OPNsense users to filter and view pf firewall metadata at a glance.

## Usage

### Packet Table Columns

Seven new optional columns are available (not shown by default):

| Column | Header | Width | Description |
|--------|--------|-------|-------------|
| `pfaction` | Action | 8 | pf action (pass, block, nat, etc.) |
| `pfdirection` | Dir | 5 | pf direction (in, out, fwd) |
| `pfinterface` | Interface | 12 | pf interface name (em0, vtnet0, etc.) |
| `pfrule` | Rule# | 6 | pf rule number |
| `pfreason` | Reason | 14 | pf reason (match, bad-offset, fragment, etc.) |
| `encspi` | SPI | 12 | IPsec enc SPI (hex) |
| `encflags` | Flags | 10 | IPsec enc flags (auth, conf, auth+conf, none) |

To enable them, add to `~/.config/tuishark/config.toml`:

```toml
[columns]
visible = ["no", "time", "source", "destination", "protocol", "length", "info", "pfaction", "pfdirection", "pfinterface", "pfreason"]
```

### Display Filters

New filter fields for pflog packets:

- `pf.action == block` — match pf action (pass, block, scrub, nat, rdr, match, etc.)
- `pf.direction == in` (alias: `pf.dir`) — match direction (in, out, fwd)
- `pf.ifname == em0` (alias: `pf.interface`) — match interface name
- `pf.rule == 42` — match rule number (numeric)
- `pf.reason == match` — match reason string (match, bad-offset, fragment, short, etc.)

New filter fields for enc (IPsec) packets:

- `enc.spi == 0x12345678` — match SPI value (hex or decimal literals supported)
- `enc.flags == 3` — match enc flags (numeric)

Hex literals are supported: `enc.spi == 0x12345678` works correctly. Both `0x` prefix (any case) and plain decimal integers are accepted.

String fields (`pf.action`, `pf.direction`, `pf.ifname`, `pf.reason`) support `contains`:

```
pf.action contains "blo"
pf.ifname contains "em"
pf.reason contains "bad"  (use quotes for values with hyphens: "bad-offset")
```

Numeric fields (`pf.rule`, `enc.spi`, `enc.flags`) support all comparison operators: `==`, `!=`, `>`, `<`, `>=`, `<=`.

All pf/enc filters return `false` for non-pflog/enc packets (safe to use on mixed captures).

### Export

All three export formats include link-layer metadata when present:

- **CSV**: Seven additional columns (`PfAction`, `PfDirection`, `PfInterface`, `PfRule`, `PfReason`, `EncSpi`, `EncFlags`) appended to every row (empty for non-pflog/enc packets)
- **JSON**: Optional fields (`pf_action`, `pf_direction`, `pf_interface`, `pf_rule`, `pf_reason`, `enc_spi`, `enc_flags`) included only when `link_meta` is present
- **Text**: Appended as `[pf: block in if=em0 rule=42 reason=match]` or `[enc: spi=0x12345678 flags=auth+conf]` after the Info column

## Configuration

No new configuration keys. The existing `[columns].visible` array accepts the new column identifiers. Link-meta columns are excluded from the default visible set to avoid clutter on standard Ethernet captures.

## Technical Details

### Performance

`PfAction` and `PfDirection` implement `as_str()` methods returning `Option<&'static str>` for zero-allocation string comparison in the hot filter evaluation path. This avoids `to_string()` heap allocation on every packet during filter evaluation. The `Unknown` variant falls back to `to_string()`.

### enc.flags decoding

The `enc_flags_str()` helper decodes the two defined bits from OpenBSD `enc(4)`:
- `M_AUTH = 0x1` — packet is authenticated
- `M_CONF = 0x2` — packet is encrypted

Decoded as: `none`, `auth`, `conf`, `auth+conf`.

### Files Modified

| File | Change |
|------|--------|
| `dissect/model.rs` | Removed `#[allow(dead_code)]`, added `as_str()` to PfAction/PfDirection, added `enc_flags_str()`, added `PartialEq` derives |
| `config/columns.rs` | Added `PfAction`, `PfDirection`, `PfInterface`, `PfRule`, `PfReason`, `EncSpi`, `EncFlags` column variants |
| `ui/widgets/packet_table.rs` | Added `cell_value` arms for all new columns |
| `filter/ast.rs` | Added `PfAction`, `PfDirection`, `PfIfname`, `PfRule`, `PfReason`, `EncSpi`, `EncFlags` field variants |
| `filter/parser.rs` | Added tokenizer mappings for `pf.*` and `enc.*` fields, hex literal (`0x`) parsing |
| `filter/eval.rs` | Added zero-alloc evaluation logic using `as_str()` for new fields |
| `export/csv.rs` | Added pflog/enc columns (including reason and flags) to CSV |
| `export/json.rs` | Added optional pflog/enc fields (including reason) to JSON |
| `export/text.rs` | Added decoded pflog/enc annotation (with reason and human-readable flags) |

### Design Choices

- New columns are **not** in the default visible set (`Column::ALL` unchanged) — only relevant for pflog/enc captures
- `Column::LINK_META` const provided for programmatic access to all link-meta columns
- Filter fields use `pf.` and `enc.` prefixes consistent with Wireshark display filter conventions
- `pf.dir` and `pf.interface` are accepted as aliases for discoverability
- Hex literal support (`0x` prefix) added to the tokenizer for intuitive SPI filtering
- `PfAction::as_str()` / `PfDirection::as_str()` avoid heap allocation on the filter hot path
- `enc.flags` decoded to human-readable names (`auth+conf`) in display, raw u32 in JSON for tooling

## Changelog

- 2026-03-14: Initial implementation — packet table columns, display filters, export for pflog/enc
- 2026-03-14: Review fixes — hex literals, pf.reason field, enc.flags decoding, as_str() hot-path optimization, PartialEq derives, comprehensive test coverage
