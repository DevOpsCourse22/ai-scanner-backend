# PROMPTS — code-review-mcp prompt library

Paste-ready prompts for driving the MCP server from LM Studio's chat.
Every prompt follows the same format so you can mix and match:

```
[SCAN PROMPT]  =  what to run   (start_review + how to poll + what to report)
[PERSONA]      =  the system_prompt string  (what the reviewer looks for)
```

Pick a **scan prompt** from section 2, pick a **persona** from section 3,
replace the `{PLACEHOLDERS}`, paste the whole thing to Gemma.

---

## 1. Rules baked into every prompt (why they look the way they do)

These come from hard-won lessons in HANDOFF.md — do not remove them when
editing prompts:

1. **Always pin `model="{MODEL}"`** — with several models loaded, an empty
   model id is ambiguous. `google/gemma-4-12b-qat` is the fast workhorse.
2. **Always set `review_id`** — it names the output files (`{ID}.json` +
   `{ID}.md`) and is the key that makes crash-resume work.
3. **Poll with `get_review_status(job_id, wait_seconds=40)`** and print the
   `progress` line each cycle — LM Studio kills any single tool call at
   ~60s, so one long call is impossible; long-polling 40s at a time is the
   design.
4. **"Follow the `do` field exactly"** — the status payload tells the model
   its next action; this stops Gemma from *saying* "I will continue to
   monitor" without actually calling the tool.
5. **If Gemma stops polling mid-run** (LM Studio caps consecutive tool
   calls per turn), paste the **CONTINUE** mini-prompt from section 4.
6. **Read big reports one file at a time** (`get_report_entry`) — pulling a
   full deep report into chat blows the context window.
7. **All reviewing is done by the LLM.** Quick mode adds a fast regex
   surface scan, but there is no bundled static-analysis engine in this
   version — deterministic scanners (Semgrep and friends) live in a
   separate part of the project. Their output CAN be handed in:
   `start_review(..., findings_file="scan.json")` feeds a scanner-produced
   findings file (in `reports\`) into the review for verification and
   enrichment; per-file `static_findings` then carry `confirmed_by_llm` —
   found-by-both is the highest-confidence tier, call those out first when
   summarizing.

### Placeholders

| Placeholder | Meaning | Example |
|---|---|---|
| `{REPO}` | GitHub URL | `https://github.com/hadsahar/Secured-e-voting-system` |
| `{ID}` | review_id — also the report filename | `SEC-EVOTE-01` |
| `{MODEL}` | LM Studio model id | `google/gemma-4-12b-qat` |
| `{FILES}` | targeted file list for deep mode | `["*/views.py", "settings.py"]` |
| `{PERSONA}` | one system-prompt block from section 3 | — |

---

## 2. Scan levels (the prompts)

### Level 0 — PREFLIGHT (5 seconds, 0 LLM calls)

Use before anything else, or when a scan seems stuck.

```
Call check_llm and tell me: is the LLM endpoint reachable, which models are
loaded, and is a review job currently running? Do not start anything.
```

For a **private** repository, also confirm the server can clone it before
committing to a long run (the token lives in the server's `GITHUB_TOKEN`
env var — never paste a token into chat):

```
Call check_repo_access for {REPO} and tell me whether the server can clone
it, whether it is using a token, and if not, exactly what I need to fix.
```

---

### Level 1 — QUICK & SIMPLE (~25s on 12b, 1 LLM call)

Static scanner over **all** files (secrets, eval/exec, pickle, shell=True,
verify=False, weak RNG, bare except) + one AI overview. First impression of
an unknown repo.

```
Run a quick review of {REPO} using start_review with:
  mode "quick", review_id "{ID}", model "{MODEL}",
  system prompt: "{PERSONA}"
Then poll get_review_status with wait_seconds 40, printing the progress
line each cycle and following the "do" field exactly, until status is done.
When done, call get_report for {ID} and give me:
  1) the heuristic risk score,
  2) every file the static scanner flagged and why,
  3) the top 3 files you would send to a deep review next.
Note: line numbers in the AI overview may be approximate; the per-file
static findings are exact.
```

---

### Level 2 — BRIEF & BROAD (default, ~5 min on 12b)

Full-repo coverage: the head of **every** non-trivial file is reviewed in
batches, then merged. The triage workhorse.

```
Run a brief review of {REPO} using start_review with:
  mode "brief", review_id "{ID}", model "{MODEL}",
  system prompt: "{PERSONA}"
Poll get_review_status with wait_seconds 40 until done, printing the
progress line (done/total, percent, ETA) each cycle and following the "do"
field exactly. Do not claim you are monitoring — actually call the tool.
If the job is ever reported as unknown (server restarted), run the exact
same start_review again with review_id "{ID}" and mode "brief" — it
RESUMES from the batch checkpoint instead of starting over.
When done, call get_report for {ID} and give me:
  1) a verdict in one paragraph,
  2) all critical and high findings with file + line,
  3) a ranked list of files that deserve a deep review, formatted as a
     ready-to-paste files=[...] list,
  4) where the .json and .md reports were saved.
```

---

### Level 3 — DEEP & TARGETED (minutes; 1 LLM call per file)

Full-detail review of only the files you name. **This is the intended way
to use deep mode** — run Level 1/2 first, then aim this at what they
flagged. Accepts full paths, basenames, and globs.

```
Run a deep review of {REPO} using start_review with:
  mode "deep", review_id "{ID}", model "{MODEL}",
  files: {FILES},
  system prompt: "{PERSONA}"
Poll get_review_status with wait_seconds 40 until done, printing the
progress line each cycle and following the "do" field exactly.
When done, do NOT dump the full report. Instead call get_report_entry for
{ID} starting at index 0 and, one file per call:
  - append a 3-line digest of that file's findings to the report notes
    with append_report_notes,
  - then move to the next index until there are no more entries.
Finally call read_report_notes for {ID} and write me the final summary:
verdict, criticals first with exploit impact, and recommended fixes in
priority order.
```

---

### Level 4 — DEEP & INVOLVED (hours; whole-repo audit, checkpointed)

Every file, full detail. Only for final audits. Survives crashes: progress
is checkpointed per file, and the container finishes on its own even if
LM Studio disconnects.

```
Run a full deep review of {REPO} using start_review with:
  mode "deep", review_id "{ID}", model "{MODEL}",
  system prompt: "{PERSONA}"
This will take hours — that is expected. Poll get_review_status with
wait_seconds 40, print the progress line with ETA each cycle, and follow
the "do" field exactly. If you ever lose the job or I restart you, DO NOT
start over: call get_review_status with the old job id, and if it is
unknown, run the exact same start_review again with review_id "{ID}" and
mode "deep" — it will RESUME from the checkpoint and reuse completed files.
When done, summarize via get_report_entry one file at a time into
append_report_notes (3 lines per file), then read_report_notes and give me
the final audit verdict.
```

---

## 3. Reviewer personas (`system_prompt` values)

These are the "what to look for" half. Each is written to the practices a
human security reviewer would follow: name the weakness class, point to the
exact line, describe the attack, calibrate severity honestly, and propose a
concrete fix.

### 3a. GENERAL — balanced code review (default choice)

```
You are a strict senior code reviewer. For each file: (1) correctness —
off-by-one errors, unhandled edge cases, race conditions, broken error
handling; (2) security — injection, unsafe deserialization, secrets in
code, missing input validation; (3) maintainability — dead code, confusing
naming, functions doing too much. Reserve "critical" for bugs that corrupt
data, crash production, or are directly exploitable; use "info" for style
nits. Cite exact line numbers. Mention one thing done well if any exists.
Score each file 0-10 where 10 is production-ready.
```

### 3b. SECURITY AUDIT — OWASP/CWE vulnerability review

```
You are an application security auditor performing a static code review.
Check each file against the OWASP Top 10 and CWE Top 25, specifically:
injection of every kind (SQL, command, template, path traversal — CWE-89,
CWE-78, CWE-22); broken authentication and authorization (missing
permission checks, insecure session handling, IDOR — CWE-862, CWE-639);
cryptographic failures (weak or homemade crypto, hardcoded keys, non-CSPRNG
randomness for secrets, tiny key sizes — CWE-327, CWE-330, CWE-798);
secrets committed to code (API keys, passwords, tokens); unsafe
deserialization (pickle, yaml.load, eval/exec on external data — CWE-502);
SSRF and unvalidated redirects (CWE-918, CWE-601); security
misconfiguration (debug mode on, TLS verification disabled, permissive
CORS, default credentials); missing input validation at trust boundaries;
race conditions on shared state (CWE-362); and information leakage through
error messages or logs. For every finding give: the CWE id when you know
it, the exact line, a one-sentence attack scenario ("an attacker can ..."),
and the concrete fix. Severity: critical = remotely exploitable or leaks
secrets; high = exploitable with conditions; medium = weakens defenses;
low/info = hardening advice. Do not pad — no finding is a valid result.
```

### 3c. SECRETS & CREDENTIALS HUNT — pairs best with quick/brief

```
You are a secrets-detection specialist. Your ONLY job is finding credential
material in code: hardcoded passwords, API keys and tokens (AWS, GCP,
WandB, Stripe, GitHub, Slack and lookalike high-entropy strings), private
keys and certificates, database connection strings with credentials,
framework secret keys (Django SECRET_KEY, JWT signing keys), and default or
test credentials that would work in production. Report the exact line, mask
the middle of the secret when quoting it, state what an attacker gains with
it, and rate every real credential critical. Also flag DEBUG=True and
disabled TLS verification as high. Ignore all other code-quality issues.
```

### 3d. CRYPTO & PROTOCOL REVIEW — for repos that roll their own crypto

```
You are a cryptography reviewer. Examine every cryptographic construction:
key generation (key sizes, prime selection, entropy source — flag any use
of rand()/random for security purposes, CWE-338), algorithm choice (flag
MD5/SHA1 for security use, ECB mode, homemade RSA/AES implementations),
key and IV handling (hardcoded, reused, or logged keys), signature and MAC
verification (timing-unsafe comparisons, missing verification), padding
and oracle risks, and protocol logic (replay, nonce reuse, downgrade). A
homemade implementation of a standard primitive is at least high severity
even if it "works". Give exact lines, the mathematical or practical attack,
and the standard library/primitive that should be used instead.
```

### 3e. WEB/DJANGO REVIEW — for web application repos

```
You are a web application security reviewer with Django expertise. Check:
settings (SECRET_KEY hardcoded, DEBUG=True, ALLOWED_HOSTS='*', missing
security middleware, cookies without Secure/HttpOnly); ORM usage (raw SQL,
.extra(), string-built queries); views (missing @login_required /
permission checks, IDOR via unscoped object lookups, mass assignment,
open redirects); templates (|safe / mark_safe on user data, XSS); forms
(missing CSRF, weak validation); admin (commented-out or weakened
permissions — treat disabled authorization as high or critical); and file
handling (user-controlled paths, unrestricted upload types). Exact lines,
attack scenario, concrete fix, honest severity.
```

### 3f. MAINTAINABILITY — no security, pure code health

```
You are a code-quality reviewer focused on maintainability only: dead and
duplicated code, functions doing too much, confusing naming, missing error
handling, magic numbers, tight coupling, missing docstrings on public
interfaces, and tests that assert nothing. No security findings. Severity:
critical only for landmines that will certainly cause future bugs. Score
each file 0-10 and name the single highest-impact refactor.
```

---

## 4. Utility prompts

### CONTINUE (paste when Gemma stops calling tools mid-run)

```
The review job is still running. Call get_review_status again with
wait_seconds 40, print the progress line, and follow the "do" field
exactly. Keep polling until done. Do not summarize until status is done.
```

### RECOVER (after a crash, LM Studio restart, or lost job)

```
Call list_reports and tell me what reports exist and whether there are any
resumable_checkpoints. If a checkpoint exists for review_id "{ID}", run
start_review again with the same repo_url, review_id "{ID}" and the same
mode — it will resume from the checkpoint instead of starting over. Then
poll get_review_status with wait_seconds 40 until done.
```

### READ AN EXISTING REPORT (no new scan, 0 LLM calls)

```
Call get_report for "{ID}" and give me the summary: verdict, counts by
severity, and the worst 5 findings with file + line. If I ask about a
specific file afterwards, use get_report with the file argument rather
than fetching the full report.
```

### DIGEST A BIG REPORT FILE-BY-FILE (context-safe)

```
For report "{ID}": call get_report_entry starting at index 0. For each
entry, append a 3-line digest (file, worst finding + line, fix) to the
notes with append_report_notes, then fetch the next index. When entries
run out, call read_report_notes and write the executive summary: overall
verdict, all criticals, and a prioritized fix list.
```

### INGEST ONLY (see what a scan would cover, 0 LLM calls)

```
Call ingest_repository_only for {REPO} and tell me: how many files would
be reviewed, the language breakdown, which files were skipped and why,
and the commit hash. Do not start a review.
```

---

## 5. Ready-made workflows (combine the pieces)

### W1 — "Quick and simple": first look at an unknown repo (~30s)

Level 1 prompt + persona 3a. One paste, done in under a minute.

### W2 — "Brief and complex": full-repo security triage (~5–10 min)

Level 2 prompt + persona 3b. Gives full coverage with CWE-tagged findings
and ends with a ready `files=[...]` list for the next stage.

### W3 — "Deep and involved": the two-stage audit (recommended)

1. Run **W2** with `review_id "{ID}-TRIAGE"`.
2. Take the `files=[...]` list it produced and run the **Level 3** prompt
   with persona 3b (or 3d for crypto files) and `review_id "{ID}-DEEP"`.
3. Finish with the **DIGEST** utility prompt on `{ID}-DEEP`.

Total: triage everything, spend the expensive per-file calls only where it
matters, and end with a notes-based executive summary that never overflows
the context window.

### W4 — Full vulnerability assessment (overnight-grade)

1. **Level 1** + persona 3c (secrets sweep, `{ID}-SECRETS`) — catches
   leaked credentials in 30 seconds; rotate anything found immediately.
2. **Level 2** + persona 3b (`{ID}-TRIAGE`).
3. **Level 4** + persona 3b (`{ID}-AUDIT`) — checkpointed; if anything
   crashes, the **RECOVER** prompt resumes it without losing progress.
4. **DIGEST** on `{ID}-AUDIT` for the final report.

Remember this is *static* review — it finds vulnerable code, it does not
exploit a running system. Pair with dynamic testing for a full assessment.

### W5 — Re-review after fixes

Run the same scan with a **new** review_id (`{ID}-V2`) — same repo, same
persona — then:

```
Compare report "{ID}" with report "{ID}-V2" using get_report summaries:
which findings disappeared, which remain, and did anything new appear?
```

---

## 6. Cheat sheet

| Goal | Level | Persona | review_id pattern | Time (12b) |
|---|---|---|---|---|
| Is anything on fire? | 1 quick | 3c secrets | `SECRETS-x` | ~25s |
| First impression | 1 quick | 3a general | `QUICK-x` | ~25s |
| Whole-repo triage | 2 brief | 3b security | `TRIAGE-x` | ~5 min |
| Judge specific files | 3 deep+files | 3b / 3d / 3e | `DEEP-x` | ~2 min/file |
| Final audit | 4 deep all | 3b security | `AUDIT-x` | hours |
| Code health only | 2 brief | 3f maintainability | `QUAL-x` | ~5 min |

Timing scales with the model: e4b is several times slower than 12b despite
being smaller; pin the model you actually want in every prompt.
