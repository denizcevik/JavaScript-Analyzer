#!/usr/bin/env python3

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
import yaml


@dataclasses.dataclass
class Pattern:
    name: str
    regex: str
    flags: str = ""
    group: int = 0
    tags: List[str] = dataclasses.field(default_factory=list)
    _compiled: Optional[re.Pattern] = None

    def compile(self) -> re.Pattern:
        if self._compiled is not None:
            return self._compiled
        fl = 0
        f = (self.flags or "").lower()
        if "i" in f:
            fl |= re.IGNORECASE
        if "m" in f:
            fl |= re.MULTILINE
        if "s" in f:
            fl |= re.DOTALL
        self._compiled = re.compile(self.regex, fl)
        return self._compiled


def read_lines_file(p: Path) -> List[str]:
    out: List[str] = []
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def safe_filename_from_url(url: str) -> str:
    u = urlparse(url)
    base = Path(u.path).name or "index"
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    if not base.lower().endswith(".js"):
        base = f"{base}.js"
    h = hashlib.sha256(url.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{base}.{h}.js"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_patterns(config_path: Path) -> Tuple[List[Pattern], Dict[str, Any]]:
    cfg = yaml.safe_load(config_path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(cfg, dict) or "patterns" not in cfg:
        raise ValueError("Config must contain a top-level 'patterns:' mapping.")
    pats: List[Pattern] = []
    for name, meta in (cfg.get("patterns") or {}).items():
        if not isinstance(meta, dict) or "regex" not in meta:
            continue
        pats.append(
            Pattern(
                name=str(name),
                regex=str(meta["regex"]),
                flags=str(meta.get("flags", "") or ""),
                group=int(meta.get("group", 0) or 0),
                tags=list(meta.get("tags", []) or []),
            )
        )
    behavior = {
        "scope": cfg.get("scope", {"allow": [], "deny": []}),
        "list": cfg.get("list", {"name": "matches", "source_tags": True, "lowercase": False, "sort": True, "dedupe": True}),
    }
    return pats, behavior


def within_scope(pattern: Pattern, behavior: Dict[str, Any]) -> bool:
    scope = behavior.get("scope") or {}
    allow = set(str(x) for x in (scope.get("allow") or []))
    deny = set(str(x) for x in (scope.get("deny") or []))
    tags = set(str(t) for t in (pattern.tags or []))
    if deny and (deny & tags):
        return False
    if allow:
        return bool(allow & tags)
    return True


def is_probably_html(headers: Dict[str, str], content: bytes, url: str) -> bool:
    ct = (headers.get("content-type") or "").lower()
    if "text/html" in ct or "application/xhtml" in ct:
        return True
    s = content[:200].lstrip().lower()
    if s.startswith(b"<!doctype") or s.startswith(b"<html") or s.startswith(b"<!--"):
        return True
    if urlparse(url).path.endswith(("/", "")) and b"<script" in content[:5000].lower():
        return True
    return False


def is_probably_js(headers: Dict[str, str], content: bytes, url: str) -> bool:
    ct = (headers.get("content-type") or "").lower()
    if any(x in ct for x in ["javascript", "ecmascript", "application/x-javascript"]):
        return True
    p = urlparse(url).path.lower()
    if p.endswith((".js", ".mjs", ".cjs")):
        return True
    s = content[:200].lstrip()
    return (
        s.startswith(b"//")
        or s.startswith(b"/*")
        or s.startswith(b"(function")
        or s.startswith(b"(()=>")
        or b"sourceMappingURL" in content[:5000]
    )


_SCRIPT_SRC_RE = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>""", re.IGNORECASE)
_JS_REF_RE = re.compile(r"""(?:(https?:)?//[^\s"'<>]+?\.js(?:\?[^\s"'<>]*)?)|(?:[A-Za-z0-9/_\.-]+?\.js(?:\?[A-Za-z0-9=&_%\.-]*)?)""")


def discover_js_urls_from_html(base_url: str, html_bytes: bytes) -> List[str]:
    html = html_bytes.decode("utf-8", errors="ignore")
    found: List[str] = []
    for m in _SCRIPT_SRC_RE.finditer(html):
        src = (m.group(1) or "").strip()
        if not src:
            continue
        found.append(urljoin(base_url, src))
    for m in _JS_REF_RE.finditer(html):
        u = m.group(0)
        if not u:
            continue
        found.append(urljoin(base_url, u))
    # de-dupe preserving order
    seen = set()
    out: List[str] = []
    for u in found:
        if u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def run_beautify(js_text: str, timeout: int = 30) -> Tuple[str, str]:
    if shutil.which("js-beautify"):
        try:
            p = subprocess.run(
                ["js-beautify", "--type", "js", "-"],
                input=js_text.encode("utf-8", errors="ignore"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if p.returncode == 0 and p.stdout:
                return p.stdout.decode("utf-8", errors="ignore"), "js-beautify"
        except Exception:
            pass

    if shutil.which("npx"):
        try:
            p = subprocess.run(
                ["npx", "-y", "js-beautify", "--type", "js", "-"],
                input=js_text.encode("utf-8", errors="ignore"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
            if p.returncode == 0 and p.stdout:
                return p.stdout.decode("utf-8", errors="ignore"), "npx:js-beautify"
        except Exception:
            pass

    normalized = js_text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = re.sub(r"[ \t]+", " ", normalized)
    normalized = re.sub(r"\n{3,}", "\n\n", normalized)
    return normalized, "fallback-normalize"


def extract_snippet(text: str, start: int, end: int, radius: int = 80) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    snip = text[a:b].replace("\n", "\\n")
    return snip


def analyze_text(text: str, patterns: List[Pattern], behavior: Dict[str, Any]) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for pat in patterns:
        if not within_scope(pat, behavior):
            continue
        cre = pat.compile()
        for m in cre.finditer(text):
            try:
                if pat.group and pat.group <= (m.lastindex or 0):
                    val = m.group(pat.group)
                    span = m.span(pat.group)
                else:
                    val = m.group(0)
                    span = m.span(0)
            except Exception:
                val = m.group(0)
                span = m.span(0)

            results.append({
                "pattern": pat.name,
                "match": val,
                "tags": pat.tags,
                "start": span[0],
                "end": span[1],
                "snippet": extract_snippet(text, span[0], span[1]),
            })

    opts = behavior.get("list") or {}
    if opts.get("lowercase"):
        for r in results:
            if isinstance(r.get("match"), str):
                r["match"] = r["match"].lower()

    if opts.get("dedupe", True):
        seen = set()
        ded = []
        for r in results:
            key = (r.get("pattern"), r.get("match"))
            if key in seen:
                continue
            seen.add(key)
            ded.append(r)
        results = ded

    if opts.get("sort", True):
        results.sort(key=lambda x: (x.get("pattern", ""), str(x.get("match", ""))))
    return results


def make_client(args: argparse.Namespace) -> httpx.Client:
    headers: Dict[str, str] = {}
    for h in args.header or []:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()

    limits = httpx.Limits(max_connections=args.threads * 2, max_keepalive_connections=args.threads * 2)
    return httpx.Client(
        headers=headers,
        proxy=args.proxy,
        verify=not args.insecure,
        timeout=httpx.Timeout(args.timeout),
        follow_redirects=True,
        limits=limits,
    )


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def write_bytes(p: Path, b: bytes) -> None:
    ensure_dir(p.parent)
    p.write_bytes(b)


def write_text(p: Path, s: str) -> None:
    ensure_dir(p.parent)
    p.write_text(s, encoding="utf-8", errors="ignore")


def fetch(client: httpx.Client, url: str) -> Tuple[str, int, Dict[str, str], bytes]:
    r = client.get(url)
    return url, r.status_code, dict(r.headers), r.content


def main() -> int:
    ap = argparse.ArgumentParser(description="Download + beautify + scan JS assets using patterns.yaml")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url", help="Single URL (JS or HTML)")
    src.add_argument("--urls", help="Text file with URLs (one per line)")
    ap.add_argument("--config", required=True, help="patterns.yaml path")
    ap.add_argument("--out", default="out_js_scan", help="Output directory")
    ap.add_argument("--threads", type=int, default=12, help="Number of worker threads")
    ap.add_argument("--discover-js", action="store_true", help="If URL is HTML, discover linked JS (<script src=...>) and scan them too")
    ap.add_argument("--beautify", action="store_true", help="Beautify JS before scanning (best-effort)")
    ap.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout seconds")
    ap.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    ap.add_argument("--header", action="append", help='Extra header, e.g. "Authorization: Bearer XXX" (repeatable)')
    ap.add_argument("--max-js", type=int, default=2000, help="Safety cap for discovered JS files")
    ap.add_argument("--only-status-200", action="store_true", help="Only keep HTTP 200 results")
    ap.add_argument("--max-bytes", type=int, default=15_000_000, help="Skip files larger than this many bytes")
    args = ap.parse_args()

    out_dir = Path(args.out)
    raw_dir = out_dir / "raw"
    beaut_dir = out_dir / "beautified"
    perfile_dir = out_dir / "per_file"
    ensure_dir(raw_dir); ensure_dir(beaut_dir); ensure_dir(perfile_dir)

    patterns, behavior = load_patterns(Path(args.config))
    targets = [args.url.strip()] if args.url else read_lines_file(Path(args.urls))

    with make_client(args) as client:
        # Expand to JS if discover mode is enabled
        urls_to_process: List[str] = []
        if args.discover_js:
            discovered: List[str] = []
            for u in targets:
                try:
                    _, status, headers, content = fetch(client, u)
                    if args.only_status_200 and status != 200:
                        continue
                    if is_probably_html(headers, content, u):
                        discovered.extend(discover_js_urls_from_html(u, content))
                    elif is_probably_js(headers, content, u):
                        discovered.append(u)
                except Exception as ex:
                    print(f"[!] Fetch failed for {u}: {ex}", file=sys.stderr)

            seen = set()
            for u in discovered:
                if u in seen:
                    continue
                seen.add(u)
                urls_to_process.append(u)
                if len(urls_to_process) >= args.max_js:
                    break
        else:
            urls_to_process = targets

        print(f"[*] Targets: {len(urls_to_process)} URL(s)")

        def dl_one(u: str) -> Dict[str, Any]:
            try:
                url, status, headers, content = fetch(client, u)
                if args.only_status_200 and status != 200:
                    return {"url": url, "status": status, "skipped": True, "reason": "non-200"}
                if len(content) > args.max_bytes:
                    return {"url": url, "status": status, "skipped": True, "reason": f"too-large>{args.max_bytes}"}
                if is_probably_html(headers, content, url):
                    return {"url": url, "status": status, "skipped": True, "reason": "html-content"}
                fn = safe_filename_from_url(url)
                raw_path = raw_dir / fn
                write_bytes(raw_path, content)
                return {
                    "url": url,
                    "status": status,
                    "headers": {k.lower(): v for k, v in headers.items()},
                    "raw_path": str(raw_path),
                    "sha256": sha256_bytes(content),
                    "size_bytes": len(content),
                }
            except Exception as ex:
                return {"url": u, "skipped": True, "reason": "exception", "error": str(ex)}

        downloaded: List[Dict[str, Any]] = []
        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for res in ex.map(dl_one, urls_to_process):
                downloaded.append(res)

        def analyze_one(entry: Dict[str, Any]) -> Dict[str, Any]:
            if entry.get("skipped"):
                return entry
            raw_path = Path(entry["raw_path"])
            raw_text = raw_path.read_text(encoding="utf-8", errors="ignore")

            used_text = raw_text
            beaut_method = None
            beaut_path = None
            if args.beautify:
                used_text, beaut_method = run_beautify(raw_text)
                beaut_path = beaut_dir / raw_path.name
                write_text(beaut_path, used_text)

            matches = analyze_text(used_text, patterns, behavior)

            out = dict(entry)
            out["beautify"] = bool(args.beautify)
            if beaut_method:
                out["beautify_method"] = beaut_method
            if beaut_path:
                out["beautified_path"] = str(beaut_path)
            out["matches_count"] = len(matches)
            out["matches"] = matches

            perfile = perfile_dir / f"{raw_path.stem}.json"
            write_text(perfile, json.dumps(out, ensure_ascii=False, indent=2))
            out["per_file_json"] = str(perfile)
            return out

        analyzed: List[Dict[str, Any]] = []
        with cf.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for res in ex.map(analyze_one, downloaded):
                analyzed.append(res)

    ts = time.strftime("%Y%m%d_%H%M%S")
    combined_json = out_dir / f"combined_{ts}.json"
    write_text(combined_json, json.dumps({"generated_at": ts, "args": vars(args), "count": len(analyzed), "results": analyzed}, ensure_ascii=False, indent=2))

    combined_csv = out_dir / f"findings_{ts}.csv"
    with combined_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "status", "sha256", "file", "pattern", "match", "tags", "start", "end", "snippet"])
        for e in analyzed:
            if e.get("skipped") or not e.get("matches"):
                continue
            for m in e["matches"]:
                w.writerow([
                    e.get("url",""),
                    e.get("status",""),
                    e.get("sha256",""),
                    Path(e.get("raw_path","")).name,
                    m.get("pattern",""),
                    m.get("match",""),
                    ",".join(m.get("tags") or []),
                    m.get("start",""),
                    m.get("end",""),
                    m.get("snippet",""),
                ])

    
    # --- GROUPED_SUMMARY (console-friendly) ---
    # Build a compact summary: "FindingName - detections"
    grouped: Dict[str, Dict[str, Any]] = {}
    for e in analyzed:
        if e.get("skipped") or not e.get("matches"):
            continue
        for m in e["matches"]:
            pname = m.get("pattern", "unknown")
            g = grouped.setdefault(pname, {"count": 0, "samples": [], "files": set()})
            g["count"] += 1
            g["files"].add(Path(e.get("raw_path","")).name)
            if len(g["samples"]) < 3:
                g["samples"].append(str(m.get("match",""))[:120])

    if grouped:
        print("\n[*] Findings (FindingName - detections):")
        for pname in sorted(grouped.keys()):
            g = grouped[pname]
            files_n = len(g["files"])
            samples = "; ".join(g["samples"])
            print(f"    - {pname} - {g['count']} (files: {files_n})" + (f" | samples: {samples}" if samples else ""))

        # Save a markdown summary too
        summary_md = out_dir / f"summary_{ts}.md"
        lines = ["# JS Asset Scan Summary", "", f"- Generated at: `{ts}`", f"- Files analyzed: `{sum(1 for e in analyzed if not e.get('skipped'))}`", ""]
        lines.append("## Findings")
        for pname in sorted(grouped.keys()):
            g = grouped[pname]
            lines.append(f"- **{pname}**: {g['count']} detections across {len(g['files'])} file(s)")
            if g["samples"]:
                lines.append(f"  - Samples: `{'; '.join(g['samples'])}`")
        write_text(summary_md, "\n".join(lines) + "\n")
        print(f"[*] Markdown summary: {summary_md}")
total_files = sum(1 for e in analyzed if not e.get("skipped"))
    skipped = sum(1 for e in analyzed if e.get("skipped"))
    total_findings = sum(int(e.get("matches_count") or 0) for e in analyzed if not e.get("skipped"))
    print(f"[*] Completed. Files analyzed: {total_files}, skipped: {skipped}, findings: {total_findings}")
    print(f"[*] Outputs:\n    - {combined_json}\n    - {combined_csv}\n    - per-file JSON: {out_dir / 'per_file'}")
    if args.beautify:
        print(f"    - beautified JS: {out_dir / 'beautified'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
