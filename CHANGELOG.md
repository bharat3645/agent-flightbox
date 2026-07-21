# Changelog

## 0.1.0 - 2026-07-21

First tagged release.

- `flightbox diff <baseline.jsonl> <candidate.jsonl>`: reports the
  exec/filesystem/network surface the candidate session reached that the
  baseline didn't (argv excluded from exec identity to avoid run-to-run
  noise). Exits 1 on new surface, usable as a CI gate against capability
  creep between agent runs.
- CI smoke harness: the sudo/netlink-tier section no longer assumes root
  implies a working proc-events connector. `ci/smoke.sh` now probes
  `flightbox check` for `netlink:  ok` before running the forced
  `-backend netlink` assertion, and skips that section (instead of failing)
  on kernels without `CONFIG_PROC_EVENTS` (observed on Docker Desktop's
  linuxkit VM during local verification). GitHub Actions' `ubuntu-latest`
  supports the connector, so this only changes behavior on environments
  that previously couldn't have passed the section anyway.

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
