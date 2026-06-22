"""
RakshakAI v2 — One-shot orchestrator for Phases 2 and 3 of the dataset pipeline.

Runs:
  download → clean → cwe_normalize (inline) → dedup → to_instruct → pack → validate

Idempotent. Re-runnable. Skips stages whose output already exists.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PY = sys.executable


def run(cmd: list[str]) -> None:
    print(f"\n>>> {' '.join(cmd)}\n", flush=True)
    res = subprocess.run(cmd, cwd=str(REPO))
    if res.returncode != 0:
        sys.exit(res.returncode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument("--skip-pack", action="store_true")
    ap.add_argument("--only", nargs="*", default=None,
                    help="restrict to one or more of: download, clean, dedup, instruct, pack, validate")
    args = ap.parse_args()

    stages = ["download", "clean", "dedup", "instruct", "pack", "validate"]
    if args.only:
        stages = [s for s in stages if s in args.only]

    if "download" in stages and not args.skip_download:
        run([PY, "v2/dataset/download.py"])

    if "clean" in stages:
        run([PY, "v2/dataset/clean.py"])

    if "dedup" in stages:
        run([PY, "-m", "pip", "install", "--quiet", "datasketch"])
        run([PY, "v2/dataset/dedup.py"])

    if "instruct" in stages:
        run([PY, "v2/dataset/to_instruct.py"])

    if "pack" in stages and not args.skip_pack:
        run([PY, "v2/dataset/pack.py"])

    if "validate" in stages:
        run([PY, "v2/dataset/validate.py"])

    print("\n[orchestrate] all stages done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
