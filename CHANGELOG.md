# Changelog

## 0.1.0 - 2026-07-18

First release.

- `flightbox record [flags] -- <command>`: records a process tree's
  behavior into a JSONL session file (schema v1, 0600).
- Tiered process sensor: netlink proc connector (exact fork/exec/exit with
  exit codes, needs CAP_NET_ADMIN, liveness-probed rather than trusted) with
  automatic, recorded degradation to /proc polling; child-subreaper trick
  keeps orphans observable in the polling tier.
- Filesystem sensor: recursive inotify on `-watch` roots, new-subdirectory
  auto-watch, session log self-excluded, queue overflows reported in-band.
- Network sensor: /proc/net tables joined against the tree's socket inodes;
  one event per unique connection, SYN_SENT attempts included, listeners
  excluded.
- `flightbox summary`: one-screen text digest. `flightbox report`: single
  static HTML timeline (no JavaScript, no external assets). `flightbox
  check`: probes which sensor tiers the current privilege level provides.
- Privacy: behavioral metadata only - no file contents, no payloads, no
  environment values; strict-schema audit in CI acts as a privacy canary.
- Evidence: unit + integration tests (race-enabled) including an
  unprivileged end-to-end recording test; CI smoke drives the real binary
  through poll and sudo/netlink tiers, audited by a strict session checker
  that is itself validated against an independent Python reference mock.
