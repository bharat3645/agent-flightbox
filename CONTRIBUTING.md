# Contributing to agent-flightbox

Thanks for looking under the hood. This project values small, verifiable changes.

## Ground rules

- **Every change ships with evidence.** Bug fix → a test that fails without it. Feature → tests that pin its behavior AND its failure modes. This repo documents what it *doesn't* do as carefully as what it does — PRs that quietly widen claims get asked to narrow them.
- **Zero new runtime dependencies** without an issue discussing why first. The dependency-free constraint is a feature.
- **Honest docs.** If your change has a limitation, the README states it. "Documented honestly" beats "silently best-effort".

## Getting started

```sh
go test -race -count=1 ./...
```

CI runs the same commands plus an end-to-end smoke; green CI is required, no exceptions (including for maintainers — check the history: it's how the whole repo was built).

## Good first issues

Issues tagged `good-first-issue` are scoped to be completable without deep context; each states the acceptance evidence expected. If you want one and it's unclear, comment — you'll get a response, not silence.

## Reporting security issues

Email 404ghost.2@gmail.com rather than opening a public issue. You'll get an acknowledgment within 48h and honest handling: if it's real, it ships as a fix with credit; if it's out of threat model, the threat-model doc gets clearer about why.
