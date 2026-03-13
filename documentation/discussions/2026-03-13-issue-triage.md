---
title: "Issue Triage — March 2026"
date: 2026-03-13
author: agent
status: active
related_issues: [6, 9, 27, 32]
related_mrs: [30]
---

## Context

Reviewed all open GitLab issues against merged MRs to identify stale issues and prioritize remaining work.

## Closed (completed work, MR already merged)

| Issue | Title | Closed by |
|-------|-------|-----------|
| #8 | Phase 5: Display filter engine | MR !7 |
| #14 | Phase 8: Packet export | MR !10 |
| #15 | Phase 9: Configuration system | MR !11 |
| #16 | Packet detail pane does not scroll | MR !12 |

All four were closed during this triage session.

## Remaining open issues

| Issue | Type | Priority | Notes |
|-------|------|----------|-------|
| #32 | Phase 11: FreeBSD base port | Feature / Next up | Depends on Phase 10 (done). Ready to start. Cross-compile with `cross` for `x86_64-unknown-freebsd`, test on OPNsense box. |
| #9 | Filter enhancements (CIDR, bare protocol, aliases, VLAN, TCP flags, IPv6) | Enhancement / Medium | Follow-up from Phase 5 review. Nine sub-items; can be tackled incrementally. |
| #27 | eBPF CO-RE/BTF migration for sk_buff offsets | Enhancement / Medium | Portability fix. Only affects path tracing probes, not process tracing. Not urgent unless targeting diverse kernel configs. |
| #6 | tshark read timeout in deep dissection | Enhancement / Low | Best deferred until tokio is introduced. Low probability in practice. |

## Merged during triage

| MR | Title |
|----|-------|
| !30 | docs: roadmap for FreeBSD portability and network visibility (phases 10-17) |

## Recommendations

- **Next milestone:** Phase 11 (#32) — FreeBSD base port. All prerequisites are met (Phase 10 merged).
- **Quick wins from #9:** bare protocol syntax and expanded protocol classification are high-value, low-effort items that improve daily usability.
- **#27 and #6** can remain in the backlog until their respective enabling work lands (diverse kernel testing, tokio migration).
