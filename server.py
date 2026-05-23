"""
RakshakAI — FastAPI inference server.
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

app = FastAPI(title="RakshakAI", version="0.2.0")
MODEL_DIR = Path("models/rakshakai-v1/")

# Try loading model
engine = None
ENGINE_MODE = "mock"
CONFIDENCE_THRESHOLD = 0.75

ID2LABEL_FALLBACK = {
    str(i): name for i, name in enumerate([
        "SQL_INJECTION", "XSS", "COMMAND_INJECTION", "HARDCODED_SECRET",
        "PATH_TRAVERSAL", "WEAK_CRYPTO", "SSTI", "INSECURE_DESERIALIZATION",
        "JWT_VULNERABILITY", "REDOS", "CSRF", "OPEN_REDIRECT",
        "NULL_DEREFERENCE", "MEMORY_LEAK", "EMPTY_CATCH", "BUFFER_OVERFLOW",
        "RACE_CONDITION", "INFINITE_LOOP", "LDAP_INJECTION", "XXE_INJECTION",
        "CLEAN",
    ])
}

try:
    from rakshakai.inference import RakshakInference
    engine = RakshakInference()
    ENGINE_MODE = "lightweight"
    logger.info(f"RakshakAI loaded ({engine.model.count_params()['total']:,} params)")
except Exception as e:
    logger.warning(f"Model not available: {e}")
    logger.info("Falling back to mock engine")

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
}


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
    description: str = ""
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    fix: Optional[str] = None


class ScanResponse(BaseModel):
    issues: List[Issue]
    language: str
    total_issues: int
    scan_time_ms: float


def mock_predict(code: str):
    code_lower = code.lower()
    if "select" in code_lower and ("+" in code_lower or 'f"' in code_lower or "${" in code_lower):
        return "SQL_INJECTION", 0.95
    if "os.system" in code_lower or "exec(" in code_lower:
        return "COMMAND_INJECTION", 0.92
    if "password =" in code_lower or "api_key" in code_lower:
        return "HARDCODED_SECRET", 0.88
    return "CLEAN", 0.99


def scan_code_by_lines(code: str, language: str, window_size: int = 5):
    lines = code.split("\n")
    issues = []
    seen = set()

    for i in range(0, len(lines), max(1, window_size // 2)):
        snippet = "\n".join(lines[i:i + window_size])
        if len(snippet.strip()) < 5:
            continue

        if engine:
            result = engine.predict(snippet, language)
            label, confidence = result["label"], result["confidence"]
        else:
            label, confidence = mock_predict(snippet)

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
            cwe=CWE_MAP.get(label, "CWE-000"),
        ))
    return issues


@app.post("/ml/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    try:
        start = time.time()
        issues = scan_code_by_lines(request.code, request.language)
        elapsed = round((time.time() - start) * 1000, 2)
        return ScanResponse(issues=issues, language=request.language,
                           total_issues=len(issues), scan_time_ms=elapsed)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ml/health")
async def health():
    return {"status": "ok", "engine": ENGINE_MODE,
            "labels": len(ID2LABEL_FALLBACK), "version": "0.2.0"}


if __name__ == "__main__":
    port = 8000
    logger.info(f"RakshakAI server starting on :{port} (engine: {ENGINE_MODE})")
    uvicorn.run(app, host="0.0.0.0", port=port)
