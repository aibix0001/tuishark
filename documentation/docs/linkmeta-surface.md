---
title: "LinkMeta Surface: pflog/enc in Packet Table, Filters & Export"
date: 2026-03-14
author: agent
status: active
related_issues: [33]
related_mrs: []
---

## Overview

Phase 10 added pflog and enc link-layer parsing, populating `PacketSummary.link_meta` with pflog action/direction/interface/rule and enc SPI/flags. However, this metadata was only rendered in the detail tree — the packet table, display filter engine, and export modules could not access it.

This change surfaces `LinkMeta` across the full UI and export pipeline, enabling FreeBSD/OPNsense users to filter and view pf firewall metadata at a glance.

## Usage

### Packet Table Columns

Five new optional columns are available (not shown by default):

| Column | Header | Width | Description |
|--------|--------|-------|-------------|
| `pfaction` | Action | 8 | pf action (pass, block, nat, etc.) |
| `pfdirection` | Dir | 5 | pf direction (in, out, fwd) |
| `pfinterface` | Interface | 12 | pf interface name (em0, vtnet0, etc.) |
| `pfrule` | Rule# | 6 | pf rule number |
| `encspi` | SPI | 12 | IPsec enc SPI (hex) |

To enable them, add to `~/.config/tuishark/config.toml`:

```toml
[columns]
visible = ["no", "time", "source", "destination", "protocol", "length", "info", "pfaction", "pfdirection", "pfinterface"]
```

### Display Filters

New filter fields for pflog packets:

- `pf.action == block` — match pf action (pass, block, scrub, nat, rdr, match, etc.)
- `pf.direction == in` (alias: `pf.dir`) — match direction (in, out, fwd)
- `pf.ifname == em0` (alias: `pf.interface`) — match interface name
- `pf.rule == 42` — match rule number (numeric)

New filter fields for enc (IPsec) packets:

- `enc.spi == 305419896` — match SPI value (numeric, decimal)
- `enc.flags == 3` — match enc flags (numeric)

String fields (`pf.action`, `pf.direction`, `pf.ifname`) support `contains`:

```
pf.action contains "blo"
pf.ifname contains "em"
```

Numeric fields (`pf.rule`, `enc.spi`, `enc.flags`) support all comparison operators: `==`, `!=`, `>`, `<`, `>=`, `<=`.

All pf/enc filters return `false` for non-pflog/enc packets (safe to use on mixed captures).

### Export

All three export formats include link-layer metadata when present:

- **CSV**: Five additional columns (`PfAction`, `PfDirection`, `PfInterface`, `PfRule`, `EncSpi`) appended to every row (empty for non-pflog/enc packets)
- **JSON**: Optional fields (`pf_action`, `pf_direction`, `pf_interface`, `pf_rule`, `enc_spi`, `enc_flags`) included only when `link_meta` is present
- **Text**: Appended as `[pf: block in if=em0 rule=42]` or `[enc: spi=0x12345678 flags=3]` after the Info column

## Configuration

No new configuration keys. The existing `[columns].visible` array accepts the new column identifiers. Link-meta columns are excluded from the default visible set to avoid clutter on standard Ethernet captures.

## Technical Details

### Files Modified

| File | Change |
|------|--------|
| `dissect/model.rs` | Removed `#[allow(dead_code)]` from `LinkMeta` and `link_meta` field |
| `config/columns.rs` | Added `PfAction`, `PfDirection`, `PfInterface`, `PfRule`, `EncSpi` column variants |
| `ui/widgets/packet_table.rs` | Added `cell_value` arms for new columns |
| `filter/ast.rs` | Added `PfAction`, `PfDirection`, `PfIfname`, `PfRule`, `EncSpi`, `EncFlags` field variants |
| `filter/parser.rs` | Added tokenizer mappings for `pf.*` and `enc.*` fields |
| `filter/eval.rs` | Added evaluation logic for new fields against `pkt.link_meta` |
| `export/csv.rs` | Added pflog/enc columns to CSV header and rows |
| `export/json.rs` | Added optional pflog/enc fields to JSON `ExportPacket` struct |
| `export/text.rs` | Added pflog/enc annotation after Info column |

### Design Choices

- New columns are **not** in the default visible set (`Column::ALL` unchanged) — only relevant for pflog/enc captures
- `Column::LINK_META` const provided for programmatic access to all link-meta columns
- Filter fields use `pf.` and `enc.` prefixes consistent with Wireshark display filter conventions
- `pf.dir` and `pf.interface` are accepted as aliases for discoverability
- Numeric fields (rule, SPI, flags) use `cmp_int` for proper numeric comparison
- String fields use case-insensitive comparison consistent with existing filter behavior
