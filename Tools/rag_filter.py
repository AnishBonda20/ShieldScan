"""
RAG-based false-positive filter for the rootkit scanner.

SECURITY POLICY — LOCAL ONLY
-----------------------------
This module operates ENTIRELY offline.  No scan data, file names, paths,
process names, registry keys, or any other system information ever leaves
this machine.  Specifically:

  • No network sockets are opened.
  • No HTTP/HTTPS calls are made.
  • No external APIs are contacted.
  • No telemetry or analytics are collected.
  • The only I/O is reading / writing the local JSON knowledge base.

The only external library used is Python's own 'difflib' (stdlib).
If you ever see an import of 'requests', 'urllib', 'httpx', 'socket'
or any networking library in this file, treat that as a security defect.

How it works
------------
1. Loads a local knowledge base (JSON) listing known-benign publishers,
   task-name patterns, safe paths, and shortcut names.
2. Normalises incoming finding attributes and checks them using exact,
   prefix and fuzzy matching (difflib only).
3. Returns (is_benign, confidence, reason) so callers decide whether to
   suppress or downgrade a finding.
4. Exposes learn() so users can mark false positives as benign; the entry
   is appended to the local JSON and reused in future scans.

Knowledge-base location:
    Tools/knowledge_base/benign_entries.json
"""
from __future__ import annotations

# ── stdlib only — NO network imports ──────────────────────────────────────
import difflib
import json
import logging
import os
import re

# Hard assertion: if any network module is accidentally imported, fail loudly.
# (This guard runs at import time.)
import sys as _sys
_FORBIDDEN = {"requests", "urllib3", "httpx", "aiohttp", "httplib2",
              "boto3", "botocore", "openai", "anthropic", "google.generativeai"}
_loaded_net = _FORBIDDEN & set(_sys.modules)
if _loaded_net:
    raise ImportError(
        f"RAGFilter security violation: network module(s) already loaded: "
        f"{_loaded_net}.  The RAG filter must remain 100% local."
    )

log = logging.getLogger(__name__)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_KB_PATH = os.path.join(_HERE, "knowledge_base", "benign_entries.json")

# SID suffix pattern on scheduled-task names, e.g. "ZoomUpdateTaskUser-S-1-5-21-..."
_SID_RE = re.compile(r"-S-\d+-\d+-\d+.*$", re.I)


def _norm(s: str) -> str:
    """Lowercase, collapse whitespace, strip leading/trailing slashes."""
    return re.sub(r"\s+", " ", s.strip().lower()).strip("/\\")


def _strip_sid(name: str) -> str:
    """Remove SID suffix from task names for fuzzy matching."""
    return _SID_RE.sub("", name).strip("-_ ").lower()


# ─────────────────────────────────────────────────────────────────────────────

class RAGFilter:
    """Knowledge-base-backed false-positive suppressor."""

    def __init__(self, kb_path: str = _KB_PATH):
        self._kb_path = kb_path
        self._kb: dict = {}
        self._load()

    # ── I/O ───────────────────────────────────────────────────────────────

    def _load(self):
        if os.path.exists(self._kb_path):
            try:
                with open(self._kb_path, encoding="utf-8") as f:
                    self._kb = json.load(f)
            except Exception as exc:
                log.warning("RAGFilter: could not load KB: %s", exc)
                self._kb = {}
        else:
            self._kb = {}

    def _save(self):
        os.makedirs(os.path.dirname(self._kb_path), exist_ok=True)
        try:
            with open(self._kb_path, "w", encoding="utf-8") as f:
                json.dump(self._kb, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            log.warning("RAGFilter: could not save KB: %s", exc)

    def reload(self):
        """Re-read the knowledge base from disk."""
        self._load()

    # ── Public API ────────────────────────────────────────────────────────

    def check(
        self,
        name: str = "",
        path: str = "",
        publisher: str = "",
        kind: str = "",
    ) -> tuple[bool, float, str]:
        """
        Return (is_benign, confidence 0-1, reason_string).

        Parameters
        ----------
        name      : task/service/lnk name
        path      : executable or file path
        publisher : Authenticode publisher string
        kind      : finding type hint ("task", "lnk", "service", "wmi", ...)
        """
        name_n      = _norm(name)
        path_n      = _norm(path)
        publisher_n = _norm(publisher)
        name_sid    = _strip_sid(name_n)

        # 1. Publisher exact / substring match (high confidence)
        if publisher_n:
            for pub in self._kb.get("publishers", []):
                p = _norm(pub)
                if p and (p in publisher_n or publisher_n in p):
                    return True, 0.95, f"Trusted publisher: {pub}"

            # 2. Fuzzy publisher match (medium confidence)
            pub_list = [_norm(p) for p in self._kb.get("publishers", []) if p]
            close_pub = difflib.get_close_matches(publisher_n, pub_list, n=1, cutoff=0.82)
            if close_pub:
                return True, 0.80, f"Publisher similar to known-benign: {close_pub[0]}"

        # 3. Safe path prefix
        if path_n:
            for sp in self._kb.get("safe_paths", []):
                sp_n = _norm(sp)
                if sp_n and path_n.startswith(sp_n):
                    return True, 0.90, f"Executable in trusted path: {sp}"

        # 4. Task / service name — prefix match
        prefixes = [_norm(p) for p in self._kb.get("task_prefixes", []) if p]
        for pfx in prefixes:
            if name_n.startswith(pfx) or name_sid.startswith(pfx.strip("/")):
                return True, 0.92, f"Task matches trusted prefix: {pfx}"

        # 5. Exact name match (tasks, services, lnk)
        exact_names = [_norm(n) for n in
                       self._kb.get("task_names", []) +
                       self._kb.get("service_names", []) +
                       self._kb.get("safe_lnk_names", []) if n]
        if name_n in exact_names or name_sid in exact_names:
            return True, 0.95, f"Known-benign name: {name}"

        # 6. Fuzzy name match (strip SID variant)
        close_name = difflib.get_close_matches(name_sid, exact_names, n=1, cutoff=0.85) if name_sid else []
        if close_name:
            return True, 0.78, f"Name similar to known-benign: {close_name[0]}"

        # 7. User-added entries
        for entry in self._kb.get("user_entries", []):
            en = _norm(entry.get("name", ""))
            ep = _norm(entry.get("path", ""))
            if en and (en in name_n or name_n in en):
                return True, 0.90, f"User-marked benign: {entry.get('name')}"
            if ep and path_n.startswith(ep):
                return True, 0.90, f"User-marked safe path: {entry.get('path')}"

        return False, 0.0, ""

    def learn(self, name: str = "", path: str = "", note: str = ""):
        """
        Persist a user-confirmed false positive so future scans ignore it.
        """
        if "user_entries" not in self._kb:
            self._kb["user_entries"] = []
        entry: dict = {}
        if name: entry["name"] = name
        if path: entry["path"] = _norm(path)
        if note: entry["note"] = note
        if entry:
            self._kb["user_entries"].append(entry)
            self._save()
            log.info("RAGFilter: learned new benign entry: %s", entry)

    def stats(self) -> dict:
        """Return counts of KB entries by category."""
        return {
            "publishers":    len(self._kb.get("publishers", [])),
            "task_names":    len(self._kb.get("task_names", [])),
            "service_names": len(self._kb.get("service_names", [])),
            "safe_lnk":      len(self._kb.get("safe_lnk_names", [])),
            "safe_paths":    len(self._kb.get("safe_paths", [])),
            "user_entries":  len(self._kb.get("user_entries", [])),
            "total":         sum(
                len(self._kb.get(k, []))
                for k in ("publishers","task_names","service_names",
                          "safe_lnk_names","safe_paths","user_entries")
            ),
        }

    def kb_path(self) -> str:
        return self._kb_path


# Module-level singleton — import and use directly.
rag_filter = RAGFilter()
