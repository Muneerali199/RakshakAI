"""
RakshakAI — Inference Server
Supports: RakshakLightweightTransformer → mock fallback
"""
import json
import time
import logging
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("rakshakai")

app = FastAPI(title="RakshakAI Engine", version="2.0.0")

MODEL_DIR = Path("models/rakshakai-v1/")
CONFIDENCE_THRESHOLD = 0.75
ENGINE_MODE = "mock"
model = None
tokenizer = None
ID2LABEL = {}

# ── Load trained model ───────────────────────────────
try:
    import torch

    from rakshak_model import RakshakLightweightTransformer
    from rakshak_tokenizer import RakshakTokenizer

    checkpoint = torch.load(MODEL_DIR / "best_model.pt", map_location="cpu")
    cfg = checkpoint["config"]

    model = RakshakLightweightTransformer(
        vocab_size=cfg["vocab_size"],
        d_model=cfg["d_model"],
        num_heads=cfg["num_heads"],
        d_ff=cfg["d_ff"],
        num_layers=cfg["num_layers"],
        num_classes=cfg["num_classes"],
        max_len=cfg["max_length"],
        pad_token_id=0,
    )
    model.load_state_dict(checkpoint["model_state_dict"])
    model.eval()
    ID2LABEL = cfg["id2label"]

    tokenizer = RakshakTokenizer.load(str(MODEL_DIR / "rakshak_tokenizer.json"))
    ENGINE_MODE = "lightweight"
    params = sum(p.numel() for p in model.parameters())
    logger.info(f"✅ RakshakAI lightweight model loaded ({params:,} params)")
except Exception as e:
    logger.warning(f"Lightweight model not available: {e}")
    logger.info("Falling back to mock engine")

    if not ID2LABEL:
        ID2LABEL = {
            str(i): name for i, name in enumerate([
                "SQL_INJECTION", "XSS", "COMMAND_INJECTION", "HARDCODED_SECRET",
                "PATH_TRAVERSAL", "WEAK_CRYPTO", "SSTI", "INSECURE_DESERIALIZATION",
                "JWT_VULNERABILITY", "REDOS", "CSRF", "OPEN_REDIRECT",
                "NULL_DEREFERENCE", "MEMORY_LEAK", "EMPTY_CATCH", "BUFFER_OVERFLOW",
                "RACE_CONDITION", "INFINITE_LOOP", "LDAP_INJECTION", "XXE_INJECTION",
                "CLEAN",
            ])
        }

SEVERITY_MAP = {
    "SQL_INJECTION": "critical", "XSS": "critical", "COMMAND_INJECTION": "critical",
    "SSTI": "critical", "INSECURE_DESERIALIZATION": "critical", "PATH_TRAVERSAL": "critical",
    "LDAP_INJECTION": "critical", "XXE_INJECTION": "critical", "JWT_VULNERABILITY": "critical",
    "BUFFER_OVERFLOW": "critical", "CSRF": "warning", "OPEN_REDIRECT": "warning",
    "HARDCODED_SECRET": "warning", "WEAK_CRYPTO": "warning", "RACE_CONDITION": "warning",
    "MEMORY_LEAK": "warning", "NULL_DEREFERENCE": "warning", "REDOS": "warning",
    "EMPTY_CATCH": "info", "INFINITE_LOOP": "info", "CLEAN": "clean",
}

CWE_MAP = {
    "SQL_INJECTION": "CWE-89", "XSS": "CWE-79", "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL": "CWE-22", "HARDCODED_SECRET": "CWE-798", "WEAK_CRYPTO": "CWE-327",
    "SSTI": "CWE-94", "INSECURE_DESERIALIZATION": "CWE-502",
}

# ── Models ────────────────────────────────────────────
class ScanRequest(BaseModel):
    code: str
    language: str
    filename: Optional[str] = "unknown"

class Issue(BaseModel):
    type: str
    severity: str
    confidence: float
    line: Optional[int] = None
    message: str
    description: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix: Optional[str] = None

class ScanResponse(BaseModel):
    issues: List[Issue]
    language: str
    total_issues: int
    scan_time_ms: float

# ── Inference ─────────────────────────────────────────
def predict_snippet(code: str, language: str):
    if ENGINE_MODE == "mock":
        code_lower = code.lower()
        if "select" in code_lower and ("+" in code_lower or 'f"' in code_lower or "${" in code_lower):
            return "SQL_INJECTION", 0.95
        if "os.system" in code_lower or "exec(" in code_lower:
            return "COMMAND_INJECTION", 0.92
        if "password =" in code_lower or "api_key" in code_lower:
            return "HARDCODED_SECRET", 0.88
        return "CLEAN", 0.99

    import torch
    import torch.nn.functional as F

    text = f"[{language}] {code}"
    input_ids = tokenizer.encode(text, 256)
    attn_mask = [1 if t != tokenizer.pad_id else 0 for t in input_ids]

    inp = torch.tensor([input_ids], dtype=torch.long)
    mask = torch.tensor([attn_mask], dtype=torch.long)

    with torch.no_grad():
        logits = model(inp, mask)
        probs = F.softmax(logits, dim=-1)
        score, pred = probs.max(dim=-1)

    label = ID2LABEL.get(str(pred.item()), ID2LABEL.get(pred.item(), "CLEAN"))
    return label, score.item()

def scan_code_by_lines(code: str, language: str, window_size: int = 5):
    lines = code.split("\n")
    issues = []
    seen = set()

    for i in range(0, len(lines), max(1, window_size // 2)):
        snippet = "\n".join(lines[i:i + window_size])
        if len(snippet.strip()) < 5:
            continue

        label, confidence = predict_snippet(snippet, language)
        if label == "CLEAN" or confidence < CONFIDENCE_THRESHOLD:
            continue
        if label in seen:
            continue
        seen.add(label)

        issues.append(Issue(
            type=label,
            severity=SEVERITY_MAP.get(label, "info"),
            confidence=round(confidence, 3),
            line=i + 1,
            message=f"{label.replace('_', ' ').title()} Detected",
            description="Security vulnerability detected by RakshakAI.",
            cwe=CWE_MAP.get(label, "CWE-000"),
            owasp="A03:2021",
            fix="Review and apply secure coding practices.",
        ))
    return issues

# ── API ───────────────────────────────────────────────
@app.post("/ml/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    try:
        start = time.time()
        issues = scan_code_by_lines(request.code, request.language)
        elapsed = round((time.time() - start) * 1000, 2)
        return ScanResponse(
            issues=issues,
            language=request.language,
            total_issues=len(issues),
            scan_time_ms=elapsed,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ml/health")
async def health():
    return {
        "status": "ok",
        "engine": ENGINE_MODE,
        "device": "cpu",
        "labels": len(ID2LABEL),
    }

@app.get("/ml/info")
async def info():
    return {
        "model": "RakshakAI",
        "version": "2.0.0",
        "engine": ENGINE_MODE,
        "architecture": "Lightweight Transformer" if ENGINE_MODE != "mock" else "Regex Mock",
        "classes": list(ID2LABEL.values()),
        "params": sum(p.numel() for p in model.parameters()) if model else 0,
    }

if __name__ == "__main__":
    port = 8000
    logger.info(f"Starting RakshakAI server on port {port} (engine: {ENGINE_MODE})")
    uvicorn.run(app, host="0.0.0.0", port=port)
