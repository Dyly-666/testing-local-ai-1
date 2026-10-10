#!/usr/bin/env python3
"""
rag.py — SQLite FTS5 retrieval for security-assessment AI (mlx-lm / Apple Silicon).

Public API
----------
  retrieve(query, domain, top_k, kb_path) -> str
      FTS5 full-text search against the 'documents' table, domain-boosted
      re-ranking, formatted for prompt injection.

  build_rag_prompt(domain, question, kb_path) -> str
      Thin wrapper: call retrieve() and return the context block.  Returns ''
      if the DB is absent, the query is blank, or no rows match — safe to
      append to any string unconditionally.

DB schema expected
------------------
  CREATE VIRTUAL TABLE documents USING fts5(
      id, title, source_url, content, trust_level, retrieved_at
  );

  (FTS5 implicit rowid + 'rank' hidden column used for BM25 ordering.)

run.py integration (3 edits — see bottom of this file)
-------------------------------------------------------
  1. import rag
  2. ap.add_argument("--kb", default="data/knowledge_base.db")
  3. rag_context = rag.build_rag_prompt(domain, question, args.kb)
  4. SYSTEM_AD  += "\\n\\n" + rag_context   # or SYSTEM_WEB
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

# ── tunables ──────────────────────────────────────────────────────────────────

DEFAULT_KB_PATH: str = "data/knowledge_base.db"

# Maximum characters of content shown per result in the injected context.
CONTENT_PREVIEW: int = 800

# When domain-boosting: fetch this many extra rows from FTS5 so the re-ranker
# has real candidates to promote.  (top_k × POOL_FACTOR, minimum 9)
POOL_FACTOR: int = 3


# ── domain keyword tables ─────────────────────────────────────────────────────
# Keys must match the 'domain' values used in run.py (case-insensitive compare
# is done at runtime).  Values are lowercase substrings matched against the
# document title.  Longer / more-specific strings shadow shorter ones just by
# appearing in the same list — order does not matter for ranking.

_DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "ad": [
        "active directory",
        "kerberos",
        "adcs",
        "ntlm",
        "ldap",
        "asrep",
        "kerberoast",
        "kerberoasting",
        "delegation",
        "constrained delegation",
        "unconstrained delegation",
        "resource-based constrained delegation",
        "rbcd",
        "dcsync",
        "pass-the-hash",
        "pass the hash",
        "overpass the hash",
        "silver ticket",
        "golden ticket",
        "lsass",
        "mimikatz",
        "certipy",
        "bloodhound",
        "sharphound",
        "winrm",
        "netlogon",
        "samr",
        "gpo",
        "group policy",
        "rodc",
        "gmsa",
        "dmsa",
        "esc1",
        "esc4",
        "esc8",
        "petitpotam",
        "printerbug",
        "coerce",
        "responder",
        "mitm6",
        "s4u2proxy",
        "pkinit",
    ],
    "web": [
        "sql injection",
        "sqli",
        "sql",
        "xss",
        "cross-site scripting",
        "ssrf",
        "server-side request forgery",
        "ssti",
        "server-side template injection",
        "template injection",
        "rce",
        "remote code execution",
        "command injection",
        "csrf",
        "cross-site request forgery",
        "idor",
        "insecure direct object",
        "lfi",
        "local file inclusion",
        "rfi",
        "remote file inclusion",
        "file inclusion",
        "xxe",
        "xml external entity",
        "deserialization",
        "path traversal",
        "directory traversal",
        "prototype pollution",
        "open redirect",
        "clickjacking",
        "oauth",
        "jwt",
        "json web token",
        "cors",
        "websocket",
        "graphql",
        "api",
    ],
}


# ── FTS5 query sanitization ───────────────────────────────────────────────────
#
# FTS5 special characters and their handling:
#
#   "    — phrase query delimiter; UNCLOSED raises OperationalError → remove
#   ( )  — grouping; UNMATCHED raises OperationalError → remove
#   *    — prefix wildcard; safe AND useful for recall → keep (added per-token)
#   ^    — initial-token anchor; unusual, remove to avoid surprises
#   \    — escape char in some FTS5 builds → remove
#   /    — column filter separator (col:value) → remove
#
# Boolean keywords AND / OR / NOT change semantics unexpectedly when they appear
# in evidence text ("NTLM relay OR Kerberos") → strip them.  We want an
# implicit per-token prefix query, which gives the best recall for RAG.
#
# Strategy: sanitize dangerous chars, then split into tokens and reconstruct
# the query as "token1* token2* ..." (FTS5 implicit-AND prefix queries).
# This allows "kerberos*" to match "Kerberoasting", "ntlm*" to match
# "ntlmrelayx", etc., which is essential for security terminology.

_FTS5_DANGEROUS = re.compile(r'["()\^\\\/]')   # chars that break FTS5 parse
_FTS5_BOOL      = re.compile(r'\b(AND|OR|NOT)\b', re.IGNORECASE)
_FTS5_COL       = re.compile(r'\b\w+\s*:')     # col:value filter syntax
_SMART_DQUOTE   = re.compile(r'[\u201c\u201d]') # " "
_SMART_SQUOTE   = re.compile(r'[\u2018\u2019]') # ' '
_WHITESPACE     = re.compile(r'\s+')
_TOKEN          = re.compile(r'[a-zA-Z0-9_\-\.]+')  # legal FTS5 token chars

# Minimum token length to suppress noise (articles, prepositions, etc.)
_MIN_TOKEN_LEN: int = 2


def _sanitize(query: str) -> str:
    """Return a safe FTS5 prefix-query string, or '' if nothing remains.

    Processing order:
      1. Normalize smart/curly quotes to plain ASCII equivalents.
      2. Remove characters that break FTS5 parsing: " ( ) ^ \\ /
      3. Strip FTS5 boolean keywords (AND, OR, NOT).
      4. Strip column-filter syntax (word:value).
      5. Collapse whitespace, split into tokens, drop short tokens.
      6. Reassemble as "tok1* tok2* ..." (prefix queries, implicit AND).

    The resulting string is safe to pass verbatim as the FTS5 MATCH parameter
    and will match documents that contain a prefix of any query token, giving
    better recall for hyphenated/compound security terms like "Kerberoasting".
    """
    q = query.strip()
    if not q:
        return ""
    # 1. Smart quotes
    q = _SMART_DQUOTE.sub(" ", q)
    q = _SMART_SQUOTE.sub("'", q)
    # 2. Remove FTS5 parse-breaking chars (keep * for now; we'll re-add it)
    q = _FTS5_DANGEROUS.sub(" ", q)
    q = q.replace("*", " ")          # strip any user-supplied wildcards; we add ours below
    # 3. Boolean keywords
    q = _FTS5_BOOL.sub(" ", q)
    # 4. Column filter syntax
    q = _FTS5_COL.sub(" ", q)
    # 5. Tokenize (only word chars + hyphens + dots; ignore punctuation/symbols)
    tokens = [t for t in _TOKEN.findall(q) if len(t) >= _MIN_TOKEN_LEN]
    if not tokens:
        return ""
    # 6. Rebuild as OR-joined prefix queries.
    #    FTS5 implicit-AND would require EVERY token to appear in a document,
    #    which is too strict for multi-word evidence strings (e.g. "sql injection
    #    union select database" fails if the doc lacks "database").  OR gives the
    #    BM25 ranker a meaningful score for partial matches — documents that contain
    #    more query terms still rank higher — without hard-excluding any result.
    if len(tokens) == 1:
        return tokens[0] + "*"
    return " OR ".join(t + "*" for t in tokens)


# ── domain re-ranking ────────────────────────────────────────────────────────

def _domain_affinity(title: str, domain: str) -> int:
    """Return an integer affinity score for use as a sort key.

    Higher = more domain-aligned.  Currently binary (0 or 1) but the
    stable sort preserves FTS5 BM25 order within each tier.
    """
    d = domain.lower() if domain else ""
    keywords = _DOMAIN_KEYWORDS.get(d, [])
    tl = title.lower()
    for kw in keywords:
        if kw in tl:
            return 1
    return 0


def _rerank(rows: list[tuple[str, str]], domain: str) -> list[tuple[str, str]]:
    """Stable re-rank so domain-aligned titles appear before others.

    FTS5 BM25 order is preserved within each affinity tier.
    """
    return sorted(rows, key=lambda r: -_domain_affinity(r[0], domain))


# ── retrieval ────────────────────────────────────────────────────────────────

def retrieve(
    query: str,
    domain: str,
    top_k: int = 3,
    kb_path: str = DEFAULT_KB_PATH,
) -> str:
    """Query the SQLite FTS5 knowledge base and return a formatted context block.

    Args:
        query:   Natural-language question / evidence string.  Will be
                 sanitized before being passed to FTS5 MATCH.
        domain:  'ad' | 'web' | '' — controls which title keywords are
                 boosted during re-ranking.
        top_k:   Number of results to include in the returned string.
        kb_path: Path to the SQLite file.  Relative paths are resolved
                 from the current working directory.

    Returns:
        A formatted string starting with '=== RELEVANT TECHNIQUES ===' and
        containing up to top_k sections of (title, content[:800]).
        Returns '' when:
          - The DB file does not exist.
          - The query is empty after sanitization.
          - FTS5 raises OperationalError (schema mismatch, etc.).
          - No rows match the query.
    """
    db = Path(kb_path)
    if not db.exists():
        return ""

    clean_q = _sanitize(query)
    if not clean_q:
        return ""

    # Fetch a wider pool so domain re-ranking has real candidates to promote.
    fetch_limit = max(top_k * POOL_FACTOR, 9)

    try:
        con = sqlite3.connect(str(db))
        con.row_factory = sqlite3.Row
        try:
            cur = con.execute(
                # FTS5 'rank' hidden column returns BM25 score (negative: lower = better).
                # ORDER BY rank ASC gives the most relevant rows first.
                "SELECT title, content "
                "FROM documents "
                "WHERE documents MATCH ? "
                "ORDER BY rank "
                "LIMIT ?",
                (clean_q, fetch_limit),
            )
            rows: list[tuple[str, str]] = [
                (r["title"] or "", r["content"] or "")
                for r in cur.fetchall()
            ]
        finally:
            con.close()
    except sqlite3.OperationalError:
        # Covers: table/column missing, FTS5 not built, bad query residue.
        return ""

    if not rows:
        return ""

    # Domain-aware re-ranking, then trim to top_k.
    rows = _rerank(rows, domain)[:top_k]

    # Format for prompt injection.
    parts: list[str] = ["=== RELEVANT TECHNIQUES ==="]
    for title, content in rows:
        preview = content.strip()[:CONTENT_PREVIEW]
        # Blank line before each entry; two blank lines separate entries.
        parts.append(f"\n{title}\n{preview}\n")

    return "\n".join(parts)


# ── high-level entry point called by run.py ───────────────────────────────────

def build_rag_prompt(
    domain: str,
    question: str,
    kb_path: str = DEFAULT_KB_PATH,
) -> str:
    """Return a context block ready to append to SYSTEM_AD / SYSTEM_WEB.

    Safe to call unconditionally: returns '' on any failure.

    Args:
        domain:   'ad' | 'web' | '' — passed through to retrieve().
        question: The user's question or evidence string used as the FTS5 query.
        kb_path:  Path to the SQLite knowledge base (args.kb from run.py).
    """
    return retrieve(query=question, domain=domain, top_k=3, kb_path=kb_path)


# ── run.py integration ────────────────────────────────────────────────────────
# Paste these three edits into run.py exactly as shown.
#
# ┌─ EDIT 1 ── top of file, with the other imports ───────────────────────────┐
# │  import rag                                                                │
# └────────────────────────────────────────────────────────────────────────────┘
#
# ┌─ EDIT 2 ── inside the argparse block, after the --model / --adapter args ─┐
# │  ap.add_argument("--kb", default="data/knowledge_base.db",                │
# │                  help="path to SQLite FTS5 knowledge base")               │
# └────────────────────────────────────────────────────────────────────────────┘
#
# ┌─ EDIT 3 ── just before building messages / calling assessment_prompt() ───┐
# │  rag_context = rag.build_rag_prompt(domain, question, args.kb)            │
# │  if domain == "ad":                                                        │
# │      SYSTEM_AD  = SYSTEM_AD  + "\n\n" + rag_context if rag_context else SYSTEM_AD   │
# │  else:                                                                     │
# │      SYSTEM_WEB = SYSTEM_WEB + "\n\n" + rag_context if rag_context else SYSTEM_WEB  │
# └────────────────────────────────────────────────────────────────────────────┘
#
# The full run.py diff would look like (unified diff, no context needed):
#
# --- a/run.py
# +++ b/run.py
# @@ imports @@
# +import rag
#
# @@ argparse @@
# +    ap.add_argument("--kb", default="data/knowledge_base.db",
# +                    help="path to SQLite FTS5 knowledge base")
#
# @@ before messages = [...] @@
# +    rag_context = rag.build_rag_prompt(domain, question, args.kb)
# +    if domain == "ad":
# +        SYSTEM_AD  = SYSTEM_AD  + "\n\n" + rag_context if rag_context else SYSTEM_AD
# +    else:
# +        SYSTEM_WEB = SYSTEM_WEB + "\n\n" + rag_context if rag_context else SYSTEM_WEB
