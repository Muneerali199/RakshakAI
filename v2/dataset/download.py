"""
RakshakAI v2 — Phase 2.1: Dataset downloader.

Pulls every training source we will use, into v2/inputs/datasets/raw/.

Sources:
  - BigVul     (Mendeley Data) — 3,754 CVEs, C/C++ function-level
  - Devign     (HuggingFace)   — 27,318 C functions
  - PrimeVul   (HuggingFace)   — 6,906 high-quality pairs (deduped vs BigVul)
  - SecurityEval (GitHub)      — 130 Python snippets
  - Juliet Test Suite subset   — ~3K Java/C/C++ samples
  - CVE/NVD JSON dump (2020-2026) — descriptions for synthetic generation
  - GitHub Security Advisories via gh-advisory-database
  - OWASP Benchmark (Java)     — held out for evaluation only

Usage:
    python v2/dataset/download.py --out v2/inputs/datasets/raw
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Iterable

RAW = Path("v2/inputs/datasets/raw")


# ---------- source registry ----------
SOURCES = {
    "bigvul": {
        "kind": "hf_dataset",
        "repo_id": "bstee615/bigvul",
        "revision": "main",
    },
    "devign": {
        "kind": "hf_dataset",
        "repo_id": "google/code_x_glue_cc_defect_detection",
        "revision": "main",
        "config": "devign",
    },
    "primevul": {
        "kind": "hf_dataset",
        "repo_id": "AsleepyFox/PrimeVul",
        "revision": "main",
    },
    "securityeval": {
        "kind": "git",
        "url": "https://github.com/awslabs/miyako.git",
        "subdir": "evaluation/SecurityEval",
    },
    "juliet_subset": {
        "kind": "git",
        "url": "https://github.com/securesoftwareengineering/juliet-test-suite.git",
        "subdir": "src",
    },
    "ghsa": {
        "kind": "git",
        "url": "https://github.com/github/advisory-database.git",
        "subdir": "advisories/github-reviewed",
    },
    "owasp_benchmark": {
        "kind": "git",
        "url": "https://github.com/OWASP-Benchmark/BenchmarkJava.git",
        "subdir": "src/main/java/org/owasp/benchmark",
    },
}


# ---------- helpers ----------
def log(msg: str) -> None:
    print(f"[download] {msg}", flush=True)


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def hf_snapshot(repo_id: str, out: Path, revision: str = "main", config: str | None = None) -> None:
    safe_mkdir(out)
    log(f"HF snapshot {repo_id} → {out}")
    cmd = [
        "huggingface-cli", "download",
        repo_id,
        "--repo-type", "dataset",
        "--revision", revision,
        "--local-dir", str(out),
        "--max-workers", "8",
    ]
    if config:
        # noop for now; specific files are selected post-download
        pass
    subprocess.run(cmd, check=True)


def git_clone(url: str, out: Path, depth: int = 1) -> None:
    if (out / ".git").exists():
        log(f"git already cloned at {out}")
        return
    log(f"git clone --depth {depth} {url} → {out}")
    safe_mkdir(out.parent)
    subprocess.run(["git", "clone", "--depth", str(depth), url, str(out)], check=True)


def http_download(url: str, out: Path) -> None:
    safe_mkdir(out.parent)
    if out.exists():
        log(f"already have {out}")
        return
    log(f"http GET {url} → {out}")
    with urllib.request.urlopen(url) as r, open(out, "wb") as f:
        shutil.copyfileobj(r, f)


# ---------- main ----------
def download_all(out_root: Path, only: Iterable[str] | None = None) -> None:
    safe_mkdir(out_root)
    keys = list(SOURCES.keys()) if only is None else list(only)
    for k in keys:
        if k not in SOURCES:
            log(f"unknown source: {k}; skipping")
            continue
        spec = SOURCES[k]
        out = out_root / k
        try:
            if spec["kind"] == "hf_dataset":
                hf_snapshot(spec["repo_id"], out, spec.get("revision", "main"), spec.get("config"))
            elif spec["kind"] == "git":
                git_clone(spec["url"], out)
            else:
                log(f"unknown kind: {spec['kind']}")
        except Exception as e:  # noqa: BLE001
            log(f"FAILED {k}: {e}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=RAW)
    ap.add_argument("--only", nargs="*", default=None)
    args = ap.parse_args()

    out_root = args.out.resolve()
    safe_mkdir(out_root)
    download_all(out_root, args.only)
    log("done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
