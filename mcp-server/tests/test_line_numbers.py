"""Line numbers in a report must point at the code they describe.

Regression tests for the DEMO-01 report on Aviel-Amitay/kubernetes-exercises
(commit ac0fec4), where every finding was real but every line number was
wrong: path traversal reported at line 54 when it lives at 69, file read at
61 when it lives at 75. The cause was llm.py sending raw, unnumbered source
while JSON_ENFORCEMENT demanded a line number — so the model counted by eye
and drifted further the deeper into the file it read.
"""

import json

import pytest

from code_review_mcp import llm as llm_mod
from code_review_mcp import review as review_mod
from code_review_mcp.llm import clamp_issue_lines, number_lines, review_chunk
from code_review_mcp.review import split_content, split_content_with_lines

# Stand-in for the reviewed file, padded so the interesting lines sit where
# they really do: path.join on line 69, fs.writeFileSync on line 70. The
# report placed them at 54 and 55.
KUBERNETES_SERVER_JS = (
    "".join(f"const line{i} = {i};\n" for i in range(1, 69))
    + "  const filePath = path.join(FILE_STORE, req.params.name);\n"
    + "  fs.writeFileSync(filePath, req.body.content || '');\n"
)


# ---------- numbering ----------

def test_number_lines_puts_the_number_beside_the_code():
    numbered = number_lines("alpha\nbravo\ncharlie")
    assert numbered.splitlines() == ["1 | alpha", "2 | bravo", "3 | charlie"]


def test_number_lines_pads_to_a_constant_gutter_width():
    numbered = number_lines("x\n" * 10).splitlines()
    assert numbered[0] == " 1 | x"
    assert numbered[9] == "10 | x"


def test_number_lines_starts_where_the_chunk_starts():
    """Part 2 of a chunked file reports FILE lines, not chunk lines."""
    numbered = number_lines("alpha\nbravo", start_line=500).splitlines()
    assert numbered == ["500 | alpha", "501 | bravo"]


def test_the_line_that_was_misreported_now_carries_its_real_number():
    """The report said 54; the code is on 69. The model now sees the 69."""
    numbered = number_lines(KUBERNETES_SERVER_JS)
    offending = [ln for ln in numbered.splitlines() if "path.join" in ln]
    assert offending == [
        "69 |   const filePath = path.join(FILE_STORE, req.params.name);"]


# ---------- chunk offsets ----------

def test_split_content_with_lines_tracks_absolute_start_lines():
    content = "".join(f"line {i}\n" for i in range(1, 101))
    chunks = split_content_with_lines(content, 200)
    assert len(chunks) > 1
    assert chunks[0][0] == 1
    # Each chunk starts exactly where the previous one ended.
    for (start, chunk), (next_start, _) in zip(chunks, chunks[1:]):
        assert next_start == start + len(chunk.splitlines())
    assert "".join(c for _, c in chunks) == content  # still lossless


def test_split_content_wrapper_is_unchanged():
    assert split_content("short", 100) == ["short"]


# ---------- validation of what comes back ----------

@pytest.mark.parametrize("reported,expected", [
    (69, 69),        # inside the range: kept
    ("69", 69),      # a string of digits: coerced
    ("L69", 69),     # the "L42" spelling some models use
    (0, None),       # before the first line
    (5000, None),    # past the end of the file — the DEMO-01 failure mode
    (True, None),    # a bool is not a line number
    ("somewhere", None),
    (None, None),
])
def test_clamp_issue_lines(reported, expected):
    issues = [{"line": reported}]
    clamp_issue_lines(issues, 1, 92)
    assert issues[0]["line"] == expected


def test_clamp_counts_only_what_it_dropped():
    issues = [{"line": 10}, {"line": 999}, {"line": None}]
    assert clamp_issue_lines(issues, 1, 92) == 1


# ---------- the wiring: what actually reaches the model ----------

def _capture(monkeypatch):
    """Intercept the completion so no network or model is needed."""
    seen = {}

    def fake_completion(client, messages, heartbeat, max_tokens, label):
        seen["payload"] = json.loads(messages[-1]["content"])
        seen["system"] = messages[0]["content"]
        return seen.get("reply", {"file": label, "issues": [], "score": 5})

    monkeypatch.setattr(llm_mod, "_json_completion", fake_completion)
    return seen


def test_review_chunk_sends_numbered_code(monkeypatch):
    seen = _capture(monkeypatch)
    review_chunk(None, "review this", "server.js",
                 KUBERNETES_SERVER_JS, "javascript")

    code = seen["payload"]["code"]
    assert "69 |   const filePath = path.join" in code
    assert seen["payload"]["lines_shown"] == "1-70"
    # The model is told what the gutter is, so it copies rather than counts.
    assert "COPY the number" in seen["payload"]["line_numbers"]
    assert "gutter" in seen["system"]


def test_review_chunk_numbers_a_later_chunk_from_its_own_offset(monkeypatch):
    seen = _capture(monkeypatch)
    review_chunk(None, "p", "big.py", "tail_a\ntail_b\n", "python",
                 part=(2, 2), start_line=901)

    assert seen["payload"]["code"].splitlines() == ["901 | tail_a", "902 | tail_b"]
    assert seen["payload"]["lines_shown"] == "901-902"


def test_review_chunk_drops_a_line_the_model_invented(monkeypatch):
    seen = _capture(monkeypatch)
    seen["reply"] = {"file": "server.js", "score": 2, "issues": [
        {"title": "path traversal", "line": 69},     # real
        {"title": "hallucinated", "line": 4200},     # nowhere near the file
    ]}
    result = review_chunk(None, "p", "server.js",
                          KUBERNETES_SERVER_JS, "javascript")

    assert [i["line"] for i in result["issues"]] == [69, None]


def test_a_chunked_review_keeps_absolute_lines_end_to_end(monkeypatch):
    """The whole deep path: a file big enough to split still reports file
    lines, and an issue found in part 2 is not renumbered from 1."""
    monkeypatch.setattr(review_mod, "make_client", lambda: None)
    monkeypatch.setattr(review_mod.settings, "max_chunk_chars", 100)
    starts = []

    def fake_chunk(client, prompt, path, content, language, part=None,
                   heartbeat=None, start_line=1, **kwargs):
        starts.append(start_line)
        # Report the LAST line of whatever chunk we were given.
        last = start_line + len(content.splitlines()) - 1
        return {"file": path, "summary": "s", "score": 5,
                "issues": [{"severity": "low", "line": last, "title": "t"}]}

    monkeypatch.setattr(review_mod, "review_chunk", fake_chunk)
    manifest = {
        "repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
        "files": [{"path": "big.py", "language": "python",
                   "content": "".join(f"row {i}\n" for i in range(1, 61))}],
    }
    report = review_mod.review_manifest(manifest, "prompt", mode="deep")

    assert starts[0] == 1 and starts[-1] > 1        # actually chunked
    lines = [i["line"] for i in report["reviews"][0]["issues"]]
    assert lines == sorted(lines) and lines[-1] == 60


# ---------- brief mode reports lines too ----------

# Over trivial_file_chars (50 non-whitespace), so brief mode really packs it.
BRIEF_SAMPLE = (
    "import os\n"
    "def run(command):\n"
    "    return os.system(command)  # unsanitised shell execution\n"
)


def test_brief_mode_numbers_the_code_it_packs():
    batches, _ = review_mod.pack_digest_batches(
        [{"path": "a.py", "content": BRIEF_SAMPLE}])
    packed = batches[0][0]
    assert packed["code"].splitlines() == [
        "1 | import os",
        "2 | def run(command):",
        "3 |     return os.system(command)  # unsanitised shell execution",
    ]
    assert packed["lines_shown"] == "1-3"


def test_brief_mode_drops_a_key_issue_line_beyond_the_file(monkeypatch):
    monkeypatch.setattr(review_mod, "make_client", lambda: None)

    def fake_digest(client, prompt, digest, heartbeat=None):
        return {"summary": "s", "score": 4, "key_issues": [
            {"severity": "high", "file": "a.py", "line": 2, "title": "real"},
            {"severity": "high", "file": "a.py", "line": 800, "title": "invented"},
        ]}

    monkeypatch.setattr(review_mod, "review_digest", fake_digest)
    report = review_mod.review_manifest(
        {"repo_url": "https://github.com/o/r", "commit": "abc", "skipped": [],
         "files": [{"path": "a.py", "language": "python",
                    "content": BRIEF_SAMPLE}]},
        "prompt", mode="brief")

    assert [i["line"] for i in report["overall"]["key_issues"]] == [2, None]
