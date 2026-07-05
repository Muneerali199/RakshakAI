"""Background batch scanner — scan whole directories, non-blocking.

Scans directories in parallel worker threads. Shows live progress.
Results stream into memory as they complete.
"""
from __future__ import annotations
import os
import re
import json
import concurrent.futures
import threading
import time
import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

SCAN_EXTS = {".c", ".h", ".cpp", ".cc", ".hpp", ".cxx", ".py", ".js", ".ts",
             ".java", ".rs", ".go", ".rb", ".php", ".swift", ".kt", ".cs"}

# 248-class CWE taxonomy extracted from rakshak-cwe-v3-data training set
CWE_TAXONOMY: set[str] = {
    "CWE-095", "CWE-1021", "CWE-1022", "CWE-1112", "CWE-1119",
    "CWE-113", "CWE-116", "CWE-117", "CWE-1187", "CWE-1188",
    "CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-1220",
    "CWE-123", "CWE-1231", "CWE-1236", "CWE-124", "CWE-125",
    "CWE-126", "CWE-1263", "CWE-127", "CWE-128", "CWE-1284",
    "CWE-1287", "CWE-129", "CWE-130", "CWE-131", "CWE-1310",
    "CWE-1320", "CWE-1321", "CWE-1333", "CWE-1336", "CWE-134",
    "CWE-1385", "CWE-1386", "CWE-1395", "CWE-14", "CWE-15",
    "CWE-150", "CWE-153", "CWE-16", "CWE-167", "CWE-17",
    "CWE-176", "CWE-178", "CWE-180", "CWE-184", "CWE-185",
    "CWE-188", "CWE-189", "CWE-19", "CWE-190", "CWE-191",
    "CWE-193", "CWE-194", "CWE-197", "CWE-20", "CWE-200",
    "CWE-201", "CWE-203", "CWE-204", "CWE-206", "CWE-208",
    "CWE-209", "CWE-212", "CWE-22", "CWE-23", "CWE-233",
    "CWE-24", "CWE-240", "CWE-248", "CWE-250", "CWE-252",
    "CWE-254", "CWE-255", "CWE-256", "CWE-26", "CWE-264",
    "CWE-266", "CWE-269", "CWE-270", "CWE-276", "CWE-280",
    "CWE-281", "CWE-282", "CWE-284", "CWE-285", "CWE-287",
    "CWE-288", "CWE-289", "CWE-29", "CWE-290", "CWE-294",
    "CWE-295", "CWE-297", "CWE-300", "CWE-304", "CWE-305",
    "CWE-306", "CWE-307", "CWE-310", "CWE-311", "CWE-312",
    "CWE-314", "CWE-319", "CWE-321", "CWE-326", "CWE-327",
    "CWE-330", "CWE-331", "CWE-338", "CWE-339", "CWE-341",
    "CWE-345", "CWE-346", "CWE-347", "CWE-349", "CWE-35",
    "CWE-351", "CWE-352", "CWE-354", "CWE-358", "CWE-359",
    "CWE-362", "CWE-367", "CWE-369", "CWE-377", "CWE-378",
    "CWE-379", "CWE-384", "CWE-385", "CWE-388", "CWE-399",
    "CWE-400", "CWE-401", "CWE-404", "CWE-407", "CWE-409",
    "CWE-414", "CWE-415", "CWE-416", "CWE-425", "CWE-426",
    "CWE-427", "CWE-428", "CWE-434", "CWE-436", "CWE-440",
    "CWE-441", "CWE-444", "CWE-450", "CWE-451", "CWE-459",
    "CWE-460", "CWE-470", "CWE-472", "CWE-476", "CWE-488",
    "CWE-489", "CWE-494", "CWE-497", "CWE-502", "CWE-506",
    "CWE-521", "CWE-522", "CWE-532", "CWE-538", "CWE-551",
    "CWE-552", "CWE-565", "CWE-59", "CWE-601", "CWE-605",
    "CWE-61", "CWE-610", "CWE-611", "CWE-612", "CWE-613",
    "CWE-617", "CWE-621", "CWE-624", "CWE-639", "CWE-640",
    "CWE-650", "CWE-657", "CWE-665", "CWE-668", "CWE-669",
    "CWE-670", "CWE-674", "CWE-681", "CWE-682", "CWE-683",
    "CWE-684", "CWE-693", "CWE-697", "CWE-703", "CWE-704",
    "CWE-706", "CWE-707", "CWE-73", "CWE-732", "CWE-733",
    "CWE-74", "CWE-754", "CWE-755", "CWE-77", "CWE-770",
    "CWE-772", "CWE-776", "CWE-778", "CWE-779", "CWE-78",
    "CWE-787", "CWE-789", "CWE-79", "CWE-798", "CWE-80",
    "CWE-807", "CWE-821", "CWE-822", "CWE-824", "CWE-829",
    "CWE-834", "CWE-835", "CWE-843", "CWE-862", "CWE-863",
    "CWE-88", "CWE-89", "CWE-908", "CWE-909", "CWE-91",
    "CWE-913", "CWE-915", "CWE-916", "CWE-918", "CWE-922",
    "CWE-926", "CWE-927", "CWE-93", "CWE-94", "CWE-940",
    "CWE-943", "CWE-95", "CWE-98",
}

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r'(?i)(api[_-]?key|apikey)\s*=\s*["\'][A-Za-z0-9_\-]{16,}["\']', "CWE-798", "Hardcoded API key"),
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\'\s]{6,}["\']', "CWE-798", "Hardcoded password"),
    (r'(?i)(secret|token)\s*=\s*["\'][A-Za-z0-9_\-\.]{16,}["\']', "CWE-798", "Hardcoded secret/token"),
    (r'(?i)(sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,})', "CWE-798", "Hardcoded API credential"),
    (r'(?i)-----BEGIN (RSA |EC )?PRIVATE KEY-----', "CWE-312", "Hardcoded private key"),
]

SQL_CONCAT_PATTERNS: list[tuple[str, str, str]] = [
    (r'(?i)(execute|query|exec)\s*\(\s*["\'][^"\']*["\']\s*[+%]', "CWE-89", "SQL query built via string concatenation"),
    (r'(?i)\$\s*["\'][^"\']*["\']\s*\.\s*\$', "CWE-89", "Interpolated SQL query"),
    (r'(?i)["\']SELECT\s.*?["\']\s*\+', "CWE-89", "SQL string concatenation"),
]

PATH_TRAVERSAL_PATTERNS: list[tuple[str, str, str]] = [
    (r'(?i)(open|read|write|unlink|include|require)\s*\(\s*\$_(GET|POST|REQUEST)', "CWE-22", "User input in file operation"),
    (r'(?i)(cat|readfile|file_get_contents)\s*\(\s*\$_(GET|POST|REQUEST)', "CWE-22", "User input in file read"),
]

@dataclass
class ScanResult:
    file: str
    status: str  # "scanning" | "done" | "error" | "skipped"
    cwe: str = ""
    severity: str = ""
    confidence: float = 0.0  # 0.0–1.0, gates auto-fix and weights feedback loop
    summary: str = ""
    error: str = ""
    duration_ms: int = 0

    def to_dict(self):
        return {
            "file": self.file,
            "status": self.status,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "summary": self.summary,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


class BatchScanner:
    """Scan multiple files in background threads with progress reporting."""

    def __init__(self, max_workers: int = 3):
        self.max_workers = max_workers
        self.results: list[ScanResult] = []
        self._lock = threading.Lock()
        self._cancelled = False
        self._on_progress: Optional[Callable] = None

    def on_progress(self, callback: Callable):
        self._on_progress = callback

    def cancel(self):
        self._cancelled = True

    def scan_files(
        self,
        files: list[str],
        model: str = "deepseek",
        cache_check: Optional[Callable] = None,
    ) -> list[ScanResult]:
        """Scan a list of files in parallel. Blocks until all done."""
        self.results = []
        self._cancelled = False
        total = len(files)

        def scan_one(file_path: str) -> ScanResult:
            if self._cancelled:
                return ScanResult(file=file_path, status="cancelled")
            start = time.time()
            try:
                content = Path(file_path).read_text(encoding="utf-8", errors="replace")
            except Exception as e:
                return ScanResult(file=file_path, status="error", error=str(e))

            # Check cache
            if cache_check:
                cached = cache_check(file_path, content)
                if cached:
                    dur = int((time.time() - start) * 1000)
                    return ScanResult(
                        file=file_path, status="done", cwe=cached.get("cwe", ""),
                        severity=cached.get("severity", ""),
                        confidence=cached.get("confidence", 0.0),
                        summary="(cached)", duration_ms=dur,
                    )

            self._report_progress(file_path, "scanning", total)
            try:
                ext = Path(file_path).suffix.lstrip(".")
                result = scan_code_quick(content, model=model, language=ext)
                vulns = result.get("vulnerabilities", [])
                cwe = vulns[0].get("cwe", "") if vulns else ""
                sev = vulns[0].get("severity", "").lower() if vulns else ""
                conf = vulns[0].get("confidence", 0.0) if vulns else 0.0
                summary = result.get("summary", "")[:200]
                dur = int((time.time() - start) * 1000)
                return ScanResult(
                    file=file_path, status="done", cwe=cwe,
                    severity=sev, confidence=conf,
                    summary=summary, duration_ms=dur,
                )
            except Exception as e:
                dur = int((time.time() - start) * 1000)
                return ScanResult(file=file_path, status="error", error=str(e), duration_ms=dur)

        done_count = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(scan_one, f): f for f in files}
            for fut in concurrent.futures.as_completed(futures):
                if self._cancelled:
                    break
                result = fut.result()
                with self._lock:
                    self.results.append(result)
                    done_count += 1
                self._report_progress(result.file, result.status, total, done_count)

        return self.results

    def _report_progress(self, file: str, status: str, total: int, done: int = 0):
        if self._on_progress:
            self._on_progress({
                "file": file,
                "status": status,
                "total": total,
                "done": done,
            })

    def summary(self) -> dict:
        """Generate a summary of scan results."""
        total = len(self.results)
        done = [r for r in self.results if r.status == "done"]
        errors = [r for r in self.results if r.status == "error"]
        vulns = [r for r in done if r.cwe]
        critical = [r for r in vulns if r.severity and "critical" in r.severity.lower()]
        high = [r for r in vulns if r.severity and "high" in r.severity.lower()]
        return {
            "total": total,
            "scanned": len(done),
            "errors": len(errors),
            "vulnerable": len(vulns),
            "critical": len(critical),
            "high": len(high),
            "files": [r.to_dict() for r in self.results],
        }


def _load_ignore_patterns(directory: str) -> list[str]:
    """Load ignore patterns from .rakshakaignore file."""
    ignore_file = Path(directory) / ".rakshakaignore"
    patterns = []
    
    if ignore_file.exists():
        try:
            with open(ignore_file, "r") as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith("#"):
                        patterns.append(line)
        except Exception:
            pass
    
    # Add default patterns
    patterns.extend([
        "node_modules", ".git", "__pycache__", "*.pyc", ".venv", "venv",
        "dist", "build", ".cache", "target", ".pytest_cache", ".mypy_cache",
        "*.min.js", "*.bundle.js", ".next", ".nuxt", "coverage",
    ])
    
    return patterns


def _should_ignore(path: Path, base_dir: Path, patterns: list[str]) -> bool:
    """Check if path should be ignored based on patterns."""
    import fnmatch
    
    try:
        rel_path = path.relative_to(base_dir)
    except ValueError:
        return False
    
    rel_str = str(rel_path)
    
    for pattern in patterns:
        # Wildcard pattern
        if "*" in pattern:
            if fnmatch.fnmatch(rel_str, pattern) or fnmatch.fnmatch(path.name, pattern):
                return True
        # Directory or exact match
        else:
            if pattern in rel_str.split(os.sep):
                return True
    
    return False


def collect_source_files(directory: str, max_files: int = 500) -> list[str]:
    """Walk a directory and collect source files to scan, respecting .rakshakaignore."""
    files = []
    base = Path(directory)
    ignore_patterns = _load_ignore_patterns(directory)
    
    for p in base.rglob("*"):
        if p.suffix.lower() in SCAN_EXTS and p.is_file():
            # Skip ignored paths
            if _should_ignore(p, base, ignore_patterns):
                continue
            
            files.append(str(p))
            if len(files) >= max_files:
                break
    
    return sorted(files)


def _validate_cwe(cwe: str) -> str:
    """Validate a CWE against the known taxonomy. Returns normalized version or ''."""
    cwe = cwe.strip().upper()
    if cwe in CWE_TAXONOMY:
        return cwe
    # Try common variants
    if cwe.startswith("CWE") and not cwe.startswith("CWE-"):
        cwe = "CWE-" + cwe[3:]
        if cwe in CWE_TAXONOMY:
            return cwe
    return ""


def static_scan(code: str, language: str = "") -> list[dict]:
    """Pre-scan with regex patterns for well-known vulnerabilities.

    Catches secrets, SQL injection, path traversal — high-precision floor.
    Returns list of findings (same shape as model vulns) with confidence=1.0.
    """
    findings: list[dict] = []

    for pattern, cwe, name in SECRET_PATTERNS:
        for m in re.finditer(pattern, code):
            line_num = code[:m.start()].count("\n") + 1
            findings.append({
                "cwe": cwe,
                "name": name,
                "severity": "HIGH",
                "confidence": 1.0,
                "location": f"line {line_num}",
                "code": code[m.start():m.end()][:80],
                "description": f"{name} detected via pattern match",
                "fix": "Move to environment variable or secret manager",
            })

    for pattern, cwe, name in SQL_CONCAT_PATTERNS:
        if language in ("py", "js", "ts", "php", "java", "go", "rs"):
            for m in re.finditer(pattern, code):
                line_num = code[:m.start()].count("\n") + 1
                findings.append({
                    "cwe": cwe,
                    "name": name,
                    "severity": "CRITICAL",
                    "confidence": 1.0,
                    "location": f"line {line_num}",
                    "code": code[max(0, m.start()-10):m.end()+10],
                    "description": name,
                    "fix": "Use parameterized queries / prepared statements",
                })

    for pattern, cwe, name in PATH_TRAVERSAL_PATTERNS:
        for m in re.finditer(pattern, code):
            line_num = code[:m.start()].count("\n") + 1
            findings.append({
                "cwe": cwe,
                "name": name,
                "severity": "HIGH",
                "confidence": 1.0,
                "location": f"line {line_num}",
                "code": code[max(0, m.start()-10):m.end()+10],
                "description": name,
                "fix": "Sanitize user input before using in file operations",
            })

    # Deduplicate by (line, cwe)
    seen: set[tuple[int, str]] = set()
    deduped = []
    for f in findings:
        line_str = f.get("location", "")
        try:
            line_num = int(line_str.replace("line ", "")) if "line " in line_str else 0
        except ValueError:
            line_num = 0
        key = (line_num, f["cwe"])
        if key not in seen:
            seen.add(key)
            deduped.append(f)
    return deduped


def scan_code(
    code: str,
    model: str = "deepseek",
    language: str = "",
    max_tokens: int = 4096,
    voting_rounds: int = 3,
) -> dict:
    """Shared scan function — single source of prompt + parsing logic.

    Three layers:
      1. Static pre-scan (regex patterns) — high-precision floor.
      2. Model N-round self-consistency voting — real confidence via agreement rate.
      3. CWE taxonomy validation — rejects out-of-taxonomy labels.

    Called by main.py (/scan), ci.py, and mcp_server.py so every
    entry point shares the same behavior. Returns structured dict
    with vulnerabilities, summary, and _raw response.
    """
    from v2.cli.llm import chat_sync as _chat_sync
    from v2.cli.prompts import get_scan_messages as _get_scan
    cfg = _get_model_config(model)
    if not cfg:
        cfg = _get_model_config("deepseek")
    lang = language or "c"

    # Layer 1: static pre-scan
    static_findings = static_scan(code, language=lang)

    # Layer 2: self-consistency voting across N runs
    cwe_votes: dict[str, int] = {}
    severity_votes: dict[str, dict[str, int]] = {}
    all_vulns: list[dict] = []
    raw_responses: list[str] = []

    for _ in range(voting_rounds):
        messages = _get_scan(f"```{lang}\n{code}\n```", model, language=lang)
        response = _chat_sync(messages, cfg, max_tokens=max_tokens)
        raw_responses.append(response)
        data = _extract_json(response)
        if data:
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                cwe = v.get("cwe", "")
                validated = _validate_cwe(cwe)
                if not validated:
                    continue  # reject out-of-taxonomy labels
                v["cwe"] = validated
                sev = (v.get("severity", "") or "").lower()
                cwe_votes[validated] = cwe_votes.get(validated, 0) + 1
                if validated not in severity_votes:
                    severity_votes[validated] = {}
                severity_votes[validated][sev] = severity_votes[validated].get(sev, 0) + 1
                all_vulns.append(v)

    # Layer 3: merge with confidence = agreement rate
    merged_cwes: dict[str, dict] = {}
    for v in all_vulns:
        cwe = v["cwe"]
        if cwe not in merged_cwes:
            merged_cwes[cwe] = {
                "cwe": cwe,
                "name": v.get("name", ""),
                "severity": "",
                "confidence": cwe_votes.get(cwe, 1) / voting_rounds,
                "location": v.get("location", ""),
                "code": v.get("code", ""),
                "description": v.get("description", ""),
                "fix": v.get("fix", ""),
            }

    # Choose majority severity for each CWE
    for cwe, m in merged_cwes.items():
        sev_counts = severity_votes.get(cwe, {})
        if sev_counts:
            m["severity"] = max(sev_counts, key=sev_counts.get).upper()

    # Add static findings (confidence 1.0, always included)
    known_static_cwes = {f["cwe"] for f in static_findings}
    for sf in static_findings:
        if sf["cwe"] not in merged_cwes:
            merged_cwes[sf["cwe"]] = sf
        else:
            merged_cwes[sf["cwe"]]["confidence"] = 1.0

    # Build summary
    vuln_list = sorted(merged_cwes.values(), key=lambda x: -x["confidence"])
    n_vulns = len(vuln_list)
    cwe_strs = ", ".join(v["cwe"] for v in vuln_list[:5])
    if n_vulns == 0:
        summary = "No vulnerabilities found."
    else:
        summary = f"Found {n_vulns} issue(s): {cwe_strs}"

    return {
        "vulnerabilities": vuln_list,
        "summary": summary,
        "_raw": raw_responses[0] if raw_responses else "",
    }


def scan_code_quick(
    code: str,
    model: str = "deepseek",
    language: str = "",
    max_tokens: int = 4096,
) -> dict:
    """Single-pass scan without voting — for batch/CI where speed matters."""
    from v2.cli.llm import chat_sync as _chat_sync
    from v2.cli.prompts import get_scan_messages as _get_scan
    cfg = _get_model_config(model)
    if not cfg:
        cfg = _get_model_config("deepseek")
    lang = language or "c"

    static_findings = static_scan(code, language=lang)
    messages = _get_scan(f"```{lang}\n{code}\n```", model, language=lang)
    response = _chat_sync(messages, cfg, max_tokens=max_tokens)
    data = _extract_json(response)

    merged = {f["cwe"]: f for f in static_findings}
    if data:
        for v in data.get("vulnerabilities", []):
            cwe = v.get("cwe", "")
            validated = _validate_cwe(cwe)
            if validated:
                v["cwe"] = validated
                sev = (v.get("severity", "") or "").lower()
                if "confidence" not in v or v.get("confidence") is None:
                    v["confidence"] = 0.9 if sev in ("critical", "high") else 0.7
                if validated not in merged:
                    merged[validated] = v

    vuln_list = sorted(merged.values(), key=lambda x: -x.get("confidence", 0))
    n_vulns = len(vuln_list)
    if n_vulns == 0:
        summary = "No vulnerabilities found."
    else:
        cwe_strs = ", ".join(v["cwe"] for v in vuln_list[:5])
        summary = f"Found {n_vulns} issue(s): {cwe_strs}"

    return {
        "vulnerabilities": vuln_list,
        "summary": summary,
        "_raw": response,
    }


def _get_model_config(model: str):
    from v2.cli.llm import registry as _reg
    cfg = _reg.get(model)
    if not cfg:
        cfg = _reg.get("deepseek")
    return cfg


def _get_cwe_info(cwe: str) -> dict:
    """Get CVE database info and remediation links for a CWE."""
    cwe_num = cwe.replace("CWE-", "")
    
    # Common remediation patterns
    remediations = {
        "89": "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
        "79": "Sanitize and encode all user input before rendering in HTML. Use context-aware escaping.",
        "78": "Avoid executing shell commands with user input. Use safe APIs instead.",
        "22": "Validate and sanitize file paths. Use allowlists and canonicalize paths.",
        "352": "Implement CSRF tokens for state-changing operations. Use SameSite cookies.",
        "798": "Remove hardcoded credentials. Use environment variables or secret management.",
        "319": "Enforce TLS/SSL for all sensitive data transmission. Use HTTPS.",
        "287": "Implement proper authentication. Use strong password policies and MFA.",
        "862": "Implement proper authorization checks. Verify user permissions before actions.",
        "611": "Disable external entity processing in XML parsers (XXE protection).",
        "502": "Avoid deserializing untrusted data. Use safe serialization formats like JSON.",
        "918": "Validate and restrict URLs for server-side requests. Use allowlists.",
        "434": "Validate file types and content. Store uploads outside webroot.",
        "416": "Ensure memory is not accessed after being freed. Use smart pointers.",
        "476": "Check for null pointers before dereferencing.",
        "119": "Use bounds checking for all buffer operations. Prefer safe string functions.",
        "200": "Avoid exposing sensitive information in error messages or responses.",
    }
    
    remediation = remediations.get(cwe_num, "Review code for security best practices.")
    
    return {
        "cwe_url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
        "nist_url": f"https://nvd.nist.gov/vuln/search/results?cwe_id=CWE-{cwe_num}",
        "remediation": remediation,
    }


def results_to_sarif(results: list[ScanResult], tool_version: str = "3.0.0") -> dict:
    """Convert scan results to SARIF 2.1.0 format with CVE links and remediation."""
    runs = []
    tool_info = {
        "driver": {
            "name": "RakshakAI",
            "version": tool_version,
            "informationUri": "https://github.com/RakshakAI/RakshakAI",
            "semanticVersion": tool_version,
            "rules": [],
        }
    }
    rule_index = {}
    artifacts = []
    results_list = []

    for r in results:
        if r.status != "done" or not r.cwe:
            continue

        if r.cwe not in rule_index:
            idx = len(rule_index)
            rule_index[r.cwe] = idx
            
            cwe_info = _get_cwe_info(r.cwe)
            
            tool_info["driver"]["rules"].append({
                "id": r.cwe,
                "name": r.cwe,
                "shortDescription": {"text": r.summary or r.cwe},
                "fullDescription": {"text": r.summary or f"Security vulnerability: {r.cwe}"},
                "defaultConfiguration": {
                    "level": _sarif_level(r.severity),
                },
                "help": {
                    "text": cwe_info["remediation"],
                    "markdown": f"**Remediation:** {cwe_info['remediation']}\n\n**References:**\n- [CWE Database]({cwe_info['cwe_url']})\n- [NIST NVD]({cwe_info['nist_url']})",
                },
                "helpUri": cwe_info["cwe_url"],
                "properties": {
                    "tags": ["security", r.cwe.lower()],
                    "security-severity": {
                        "critical": "9.0",
                        "high": "7.0",
                        "medium": "5.0",
                        "low": "3.0",
                        "info": "1.0",
                    }.get(r.severity.lower(), "5.0"),
                },
            })

        rel_path = os.path.relpath(r.file) if os.path.isabs(r.file) else r.file
        
        cwe_info = _get_cwe_info(r.cwe)

        results_list.append({
            "ruleId": r.cwe,
            "ruleIndex": rule_index[r.cwe],
            "message": {
                "text": r.summary or f"Security finding: {r.cwe}",
                "markdown": f"**{r.cwe}:** {r.summary or 'Security vulnerability detected'}\n\n{cwe_info['remediation']}",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": rel_path, "uriBaseId": "%SRCROOT%"},
                },
            }],
            "level": _sarif_level(r.severity),
            "properties": {
                "severity": r.severity,
                "confidence": f"{r.confidence:.0%}",
                "remediation_url": cwe_info["cwe_url"],
            },
        })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": tool_info,
            "results": results_list,
        }],
    }
    return sarif


def _sarif_level(severity: str) -> str:
    sev = (severity or "").lower()
    if sev in ("critical", "high"):
        return "error"
    if sev in ("medium",):
        return "warning"
    return "note"
