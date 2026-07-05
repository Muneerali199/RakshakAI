"""Ultra-efficient security prompts - Claude Mythos intelligence, minimal tokens."""
from __future__ import annotations

from v2.cli.scanner import CWE_TAXONOMY

# Compact CWE reference (only critical ones, saves tokens)
_CRITICAL_CWES = "CWE-89,78,79,22,352,798,319,287,862,611,502,918,434,416,476,119,787,125,190,134,415,362,200"

# Ultra-compressed elite prompt - transforms any model into security genius
MYTHOS_CORE = f"""Elite security AI. Scan code for vulns. Output JSON only.

CWE taxonomy: {_CRITICAL_CWES}

Rules:
1. JSON format ONLY - no markdown, no explanations
2. CWE from list above
3. Severity: CRITICAL/HIGH/MEDIUM/LOW
4. Confidence: 0-1 (1=certain, 0.5=possible)
5. If safe: {{"vulnerabilities":[]}}

Format:
{{"vulnerabilities":[{{"cwe":"CWE-X","severity":"HIGH","confidence":0.9,"line":N,"description":"brief","fix":"code"}}]}}

Be precise. No false positives."""

# Explain mode - concise and smart
EXPLAIN_COMPACT = """Explain code concisely. Cover: purpose, key functions, security notes, edge cases. Be brief."""

# Fix mode - direct and actionable
FIX_COMPACT = """Security engineer. Provide: 1) Root cause 2) Secure fix (code) 3) Why it works. Be direct."""

# Model-specific optimizations
SYSTEM_PROMPTS = {
    "rakshak": MYTHOS_CORE,
    "deepseek": MYTHOS_CORE,  # DeepSeek benefits from ultra-compact prompts
    "llama": MYTHOS_CORE,
    "gpt-4o": MYTHOS_CORE,
    "gpt-4o-mini": MYTHOS_CORE,  # Especially important for mini models
}

def get_system(model_name: str = "deepseek") -> str:
    """Get ultra-efficient system prompt for any model."""
    return SYSTEM_PROMPTS.get(model_name, MYTHOS_CORE)

def get_scan_messages(code: str, model_name: str = "deepseek", language: str = "c") -> list[dict]:
    """Create scan messages - optimized for token efficiency."""
    # Truncate code if too long (save tokens)
    max_code_len = 4000
    if len(code) > max_code_len:
        code = code[:max_code_len] + "\n... [truncated]"
    
    lang = language or "c"
    return [
        {"role": "system", "content": get_system(model_name)},
        {"role": "user", "content": f"Scan {lang}:\n```{lang}\n{code}\n```"},
    ]

def get_explain_messages(code: str) -> list[dict]:
    """Explain code - compact prompt."""
    max_code_len = 3000
    if len(code) > max_code_len:
        code = code[:max_code_len] + "\n... [truncated]"
    
    return [
        {"role": "system", "content": EXPLAIN_COMPACT},
        {"role": "user", "content": f"```c\n{code}\n```"},
    ]

def get_fix_messages(description: str) -> list[dict]:
    """Fix vulnerability - direct prompt."""
    return [
        {"role": "system", "content": FIX_COMPACT},
        {"role": "user", "content": description[:500]},  # Limit description length
    ]

## Rules
1. NEVER hallucinate vulnerabilities. Only report what you can verify.
2. Classify every finding with an exact CWE ID from the approved list below.
3. Rate severity: CRITICAL / HIGH / MEDIUM / LOW / INFO.
4. Rate confidence: 0.0–1.0 based on how certain you are (1.0 = definite, 0.5 = plausible, 0.0 = uncertain).
5. Provide the exact line number and a snippet of vulnerable code.
6. Suggest a concrete fix for each finding.
7. If the code is safe, say so clearly — "No vulnerabilities found."

## Approved CWE taxonomy (248 classes)
Your output CWE MUST be one of these, NOT a free-generated label:
{_CWE_LIST}

## Output format (use markdown)
```json
{{
  "vulnerabilities": [
    {{
      "cwe": "CWE-XXX",
      "name": "Short name",
      "severity": "HIGH",
      "confidence": 0.95,
      "location": "file.c:42",
      "code": "gets(buf);",
      "description": "What's wrong and why it matters",
      "fix": "How to fix it with code example"
    }}
  ],
  "summary": "Overall assessment"
}}
```

## Key CWEs to watch for
- CWE-119: Buffer overflow (gets, strcpy, sprintf without bounds)
- CWE-787: Out-of-bounds write
- CWE-125: Out-of-bounds read
- CWE-476: NULL pointer dereference
- CWE-190: Integer overflow
- CWE-78: OS command injection
- CWE-134: Format string
- CWE-415: Double free
- CWE-416: Use after free
- CWE-362: Race condition
- CWE-200: Information exposure

Be thorough but honest. Quality over quantity."""

GPT4_SYSTEM = f"""You are RakshakAI, an elite security code auditor. Analyze source code for vulnerabilities.

## Requirements
- Report CWE ID (from approved 248-class taxonomy), severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), and confidence (0.0–1.0)
- Suggest a concrete, working fix for each issue
- If safe, explicitly state "No vulnerabilities found"
- Be conservative — do not report speculative issues as real vulnerabilities
- Your CWE MUST be from the approved taxonomy, NOT free-generated

## Output format
```json
{{
  "vulnerabilities": [
    {{
      "cwe": "CWE-XXX",
      "name": "...",
      "severity": "HIGH",
      "confidence": 0.95,
      "location": "...",
      "code": "...",
      "description": "...",
      "fix": "..."
    }}
  ],
  "summary": "..."
}}
```

You cross-reference findings with known exploit patterns. You are precise, not alarmist."""

GPT4_MINI_SYSTEM = """You are a security code reviewer. Analyze source code and report vulnerabilities.

For each finding provide: CWE ID (from approved 248-class taxonomy), severity (CRITICAL/HIGH/MEDIUM/LOW/INFO), confidence (0.0–1.0), location, and fix suggestion.

If the code is safe, say "No vulnerabilities found."

Be accurate — false positives waste time."""

EXPLAIN_SYSTEM = """You explain C/C++ source code clearly and concisely. Cover:
1. What the program does at a high level
2. Key functions and their purpose
3. Input/output behavior
4. Any notable security-relevant patterns (even if not vulnerabilities)
5. Potential edge cases or bugs

Be educational. Assume the reader knows C but may miss subtle issues."""

FIX_SYSTEM = """You are a senior security engineer. Given a vulnerability description, provide:
1. Root cause analysis
2. A secure code fix (complete function or snippet)
3. Explanation of why the fix works
4. Any additional hardening that could be applied

The fix must be correct, secure, and production-ready."""

SYSTEM_PROMPTS = {
    "rakshak": DEEPSEEK_SYSTEM,
    "deepseek": DEEPSEEK_SYSTEM,
    "llama": DEEPSEEK_SYSTEM,
    "gpt-4o": GPT4_SYSTEM,
    "gpt-4o-mini": GPT4_MINI_SYSTEM,
}

def get_system(model_name: str = "deepseek") -> str:
    return SYSTEM_PROMPTS.get(model_name, DEEPSEEK_SYSTEM)

def get_scan_messages(code: str, model_name: str = "deepseek", language: str = "c") -> list[dict]:
    lang = language or "c"
    return [
        {"role": "system", "content": get_system(model_name)},
        {"role": "user", "content": f"Scan this {lang} code for vulnerabilities:\n\n```{lang}\n{code}\n```"},
    ]

def get_explain_messages(code: str) -> list[dict]:
    return [
        {"role": "system", "content": EXPLAIN_SYSTEM},
        {"role": "user", "content": f"Explain this C code:\n\n```c\n{code}\n```"},
    ]

def get_fix_messages(description: str) -> list[dict]:
    return [
        {"role": "system", "content": FIX_SYSTEM},
        {"role": "user", "content": f"Fix this vulnerability:\n\n{description}"},
    ]
