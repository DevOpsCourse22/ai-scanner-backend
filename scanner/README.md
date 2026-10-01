# scanner — the deterministic tier

Runs pinned scanners over a cloned repository and normalizes their output
into the single finding format review-api ingests. Implements **FR-007**
(Semgrep, Gitleaks, Trivy, extensible by plugin) and **FR-008** (normalize
into a common internal format).

This is the *deterministic-first* half of the platform: scanners produce
evidence, and the LLM's job is **enrichment** of that evidence — verify,
explain, prioritize, suggest a fix — not discovery from scratch.

```
repo-scan <repo> → findings.json → review-api (findings_file=…) → enriched report
```

## Use

```bash
pip install -e ./Code-Review-MCP/scanner
repo-scan /path/to/clone -o reports/EVOTE.findings.json
```

Then reference the file by name when starting a review:

```json
{"review_id": "EVOTE-01", "repo_url": "…", "findings_file": "EVOTE.findings.json"}
```

`--scanners semgrep,trivy` runs a subset; `--timeout` is per scanner.

## Running it in a container (no local installs)

The image carries all three scanners, so nothing has to be installed on the
host. Trivy and Gitleaks are lifted out of their official images at build
time; Semgrep arrives as a Python dependency.

```bash
docker build -t repo-scanner ./Code-Review-MCP/scanner

docker run --rm \
  -v /path/to/clone:/workspace:ro \
  -v /path/to/reports:/reports \
  repo-scanner /workspace -o /reports/scan.findings.json
```

Mount the repository **read-only** — nothing here writes to it.

**On Windows, run this from PowerShell, or prefix it with
`MSYS_NO_PATHCONV=1` in Git Bash.** Git Bash rewrites `/workspace` into a
Windows path before Docker ever sees it, and the scan fails with
`C:/Program Files/Git/workspace is not a directory`.

The container runs as a non-root user (uid 10001). That matters more here
than for a normal service: this process parses somebody else's repository,
which is exactly the input you least want handled with root privileges.

## Installing the scanners

| Scanner | Covers | Install |
|---|---|---|
| Semgrep | static code analysis | `pip install semgrep` (works natively on Windows since ~1.17x) |
| Gitleaks | committed secrets | Go binary — [releases](https://github.com/gitleaks/gitleaks/releases), or `docker run zricethezav/gitleaks` |
| Trivy | CVEs, IaC misconfig | Go binary — [releases](https://github.com/aquasecurity/trivy/releases), or `docker run aquasec/trivy` |

A scanner that is missing does **not** fail the run — it is recorded by
name in `scanners_failed`, and the CLI prints it loudly to stderr. See
"truthful coverage" below.

## Three rules worth knowing before editing

**1. Never copy matched source text.** Every one of these tools can hand
back the text it matched — Semgrep's `extra.lines`, Gitleaks' `Secret`
and `Match`, Trivy's secret matches. That text is exactly what is most
likely to *be* a credential. A finding says which rule fired and where;
it never reproduces the value. A secrets report that reprints the secret
has published it again — into a findings file, an LLM prompt, and a
stored report. `test_gitleaks_secret_value_never_reaches_the_finding`
locks this.

**2. Paths must be repo-relative, forward-slash.** Scanners report paths
relative to the directory they were pointed at, with the host separator
(`myclone\app\views.py` on Windows). The review matches findings against
its own manifest of repo-relative paths. A mismatch does not raise — the
findings just land in `unmatched` and the model gets nothing, while the
run still reports success. `repo_relative()` in `findings.py` handles it.

**3. Truthful coverage over clean-looking output.** "0 findings" and "the
scanner never ran" are different claims, and the roadmap makes telling
them apart a release gate. Hence `scanners_run`, `scanners_failed`, and
per-scanner `scanned_files` in every output document.

## Severity

Semgrep's `ERROR/WARNING/INFO` maps to `high/medium/low`, and **never to
`critical`** — a pattern match is evidence that a pattern fired, not a
judgement about blast radius. Trivy is the exception: its `CRITICAL` is
passed through, because it comes from a CVSS score published with a known
CVE, which is an external evidence-backed claim. Gitleaks has no severity
of its own; every hit is `high` — a credential in a repository is never
minor. Escalation to `critical` belongs to the enrichment tier, which can
see whether a secret is live, scoped, or already rotated.

## Adding a scanner

Write an adapter with `command()`, `parse()`, and `coverage()` (see
`adapters/base.py`), then add one line to `ADAPTERS` in
`adapters/__init__.py`. Nothing in the runner, CLI, or review pipeline
changes. Test it against a recorded sample of real tool output so it runs
in CI without the tool installed — see `tests/test_adapters.py`.
