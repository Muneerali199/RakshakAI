"""
RakshakAI v2 — CrossVul importer.

Source:  https://huggingface.co/datasets/xin1997/crossvul-{lang}_all_only_input
Format:  HF dataset for each language.

CrossVul provides labeled vulnerability data across 27 programming languages.
This is key for fixing the language imbalance (currently 100K C vs 4K Python).

Output: v2/inputs/datasets/raw/crossvul.jsonl
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from v2.dataset.importers.common import ImportStats, write_samples
from v2.dataset.schema import SecuritySample

SOURCE = "crossvul"
MAX_SAMPLES = 60_000

# CrossVul per-language datasets on HuggingFace
CROSSVUL_LANGS = {
    "cpp": "xin1997/crossvul-cpp_all_only_input",
    "java": "xin1997/crossvul-java_all_only_input",
    "python": "xin1997/crossvul-python_all_only_input",
}

LANG_MAP = {
    "cpp": "cpp", "c++": "cpp", "c": "c",
    "java": "java", "python": "python",
    "javascript": "javascript", "js": "javascript",
    "typescript": "typescript", "ts": "typescript",
    "go": "go", "golang": "go",
    "rust": "rust", "rs": "rust",
    "ruby": "ruby", "rb": "ruby",
    "php": "php",
    "csharp": "csharp", "c#": "csharp",
    "swift": "swift",
    "kotlin": "kotlin", "kt": "kotlin",
    "scala": "scala",
    "perl": "perl", "pl": "perl",
}


def main() -> int:
    stats = ImportStats(source=SOURCE)
    samples: list[SecuritySample] = []

    try:
        from datasets import load_dataset
    except ImportError:
        print("[crossvul] ERROR: datasets not installed. Run: pip install datasets")
        stats.error = "datasets not installed"
        write_samples(SOURCE, samples, stats)
        return 1

    for lang, repo_id in CROSSVUL_LANGS.items():
        print(f"[crossvul] Loading {lang} from {repo_id}...")
        try:
            dataset = load_dataset(repo_id, split="train", trust_remote_code=True)
        except Exception as e:
            print(f"  [crossvul] Failed to load {repo_id}: {e}")
            continue

        for i, row in enumerate(dataset):
            if len(samples) >= MAX_SAMPLES:
                break
            stats.requested += 1

            code = row.get("code") or row.get("func") or row.get("source") or ""
            label = row.get("label") or row.get("target") or row.get("vul") or 0
            cwe_str = row.get("cwe") or row.get("cwe_id") or ""
            cve_id = row.get("cve") or row.get("cve_id") or ""

            try:
                is_vuln = bool(int(label))
            except (ValueError, TypeError):
                is_vuln = bool(label)

            if len(code) < 30:
                stats.skipped_too_short += 1
                continue
            if len(code) > 100_000:
                continue

            actual_lang = LANG_MAP.get(lang, lang)
            if actual_lang not in ("c", "cpp", "java", "python", "javascript",
                                    "typescript", "go", "rust", "ruby", "php",
                                    "csharp", "swift", "kotlin", "scala", "perl"):
                stats.skipped_no_code += 1
                continue

            cwe = None
            if cwe_str:
                import re
                m = re.search(r"CWE-(\d+)", str(cwe_str), re.I)
                if m:
                    cwe = f"CWE-{int(m.group(1))}"

            sev = "high"
            if not is_vuln:
                sev = "clean"

            try:
                s = SecuritySample.build(
                    language=actual_lang,
                    vulnerable_code=code[:8000],
                    patched_code=None,
                    cwe=cwe,
                    severity=sev,
                    explanation=f"CrossVul {lang} sample." if is_vuln else "Non-vulnerable code from CrossVul.",
                    attack_scenario="" if not is_vuln else f"CVE: {cve_id}" if cve_id else "",
                    secure_fix="Not applicable." if not is_vuln else f"See {cve_id} fix." if cve_id else "Apply standard patch.",
                    source=f"crossvul:{cve_id}" if cve_id else f"crossvul:{lang}:{i}",
                    source_license="MIT",
                    cve=cve_id or None,
                    is_vulnerable=is_vuln,
                    split="train",
                )
            except Exception:
                stats.skipped_no_code += 1
                continue

            samples.append(s)
            stats.built += 1

        print(f"  [crossvul] {lang}: built {sum(1 for s in samples if s.source.startswith(f'crossvul:{lang}') or lang in s.source)}")

    write_samples(SOURCE, samples, stats)
    print(f"[crossvul] total: {len(samples)} samples")
    print(json.dumps(stats.to_dict(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
