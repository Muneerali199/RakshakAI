from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import json
import uvicorn
import time
import logging

app = FastAPI(title="RakshakAI Engine", version="1.0.0")
logging.basicConfig(level=logging.INFO)

# ── Global Model Setup ───────────────────────────────
# We will attempt to load the real model, but fallback to 
# a smart mock mode if it has not been trained yet.
MODEL_DIR = "models/rakshakai-v1/"
DEVICE = "cpu"
CONFIDENCE_THRESHOLD = 0.75
MOCK_MODE = False

try:
    import torch
    import torch.nn.functional as F
    from transformers import RobertaTokenizer, RobertaForSequenceClassification
    
    DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    tokenizer = RobertaTokenizer.from_pretrained(MODEL_DIR)
    model = RobertaForSequenceClassification.from_pretrained(MODEL_DIR)
    model.to(DEVICE)
    model.eval()

    with open(f"{MODEL_DIR}label_map.json") as f:
        label_map = json.load(f)
    ID2LABEL = {int(k): v for k, v in label_map["id2label"].items()}
    logging.info(f"Loaded ML model successfully on {DEVICE}")
except Exception as e:
    logging.warning(f"Could not load ML model from {MODEL_DIR}. Falling back to ML Mock Engine. Error: {e}")
    MOCK_MODE = True
    
    # Fallback mock mappings
    ID2LABEL = {
        0: "SQL_INJECTION", 1: "XSS", 2: "CSRF", 3: "PATH_TRAVERSAL", 
        4: "COMMAND_INJECTION", 5: "HARDCODED_SECRET", 20: "CLEAN"
    }

# ── Severity Map ─────────────────────────────────────
SEVERITY_MAP = {
    "SQL_INJECTION": "critical",
    "XSS": "critical",
    "COMMAND_INJECTION": "critical",
    "SSTI": "critical",
    "INSECURE_DESERIALIZATION": "critical",
    "PATH_TRAVERSAL": "critical",
    "LDAP_INJECTION": "critical",
    "XXE_INJECTION": "critical",
    "JWT_VULNERABILITY": "critical",
    "BUFFER_OVERFLOW": "critical",
    "CSRF": "warning",
    "OPEN_REDIRECT": "warning",
    "HARDCODED_SECRET": "warning",
    "WEAK_CRYPTO": "warning",
    "RACE_CONDITION": "warning",
    "MEMORY_LEAK": "warning",
    "NULL_DEREFERENCE": "warning",
    "REDOS": "warning",
    "EMPTY_CATCH": "info",
    "INFINITE_LOOP": "info",
    "CLEAN": "clean"
}

CWE_MAP = {
    "SQL_INJECTION": "CWE-89", "XSS": "CWE-79", "COMMAND_INJECTION": "CWE-78",
    "PATH_TRAVERSAL": "CWE-22", "HARDCODED_SECRET": "CWE-798", "WEAK_CRYPTO": "CWE-327"
}

OWASP_MAP = {
    "SQL_INJECTION": "A03:2021", "XSS": "A03:2021", "COMMAND_INJECTION": "A03:2021",
    "PATH_TRAVERSAL": "A01:2021", "HARDCODED_SECRET": "A07:2021", "WEAK_CRYPTO": "A02:2021"
}

# ── Request/Response Models ──────────────────────────
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

# ── Inference ────────────────────────────────────────
def predict_snippet(code: str, language: str):
    if MOCK_MODE:
        # Smart Regex Mocking to simulate the ML Engine for Demo purposes
        code_lower = code.lower()
        if "select" in code_lower and ("+" in code_lower or "f\"" in code_lower or "${" in code_lower):
            return "SQL_INJECTION", 0.95, None
        if "os.system" in code_lower or "exec(" in code_lower:
            return "COMMAND_INJECTION", 0.92, None
        if "password =" in code_lower or "api_key" in code_lower:
            return "HARDCODED_SECRET", 0.88, None
        return "CLEAN", 0.99, None
    else:
        # Real ML inference
        text = f"[{language.upper()}] {code}"
        encoding = tokenizer(
            text, max_length=512, padding='max_length', truncation=True, return_tensors='pt'
        )
        input_ids = encoding['input_ids'].to(DEVICE)
        attention_mask = encoding['attention_mask'].to(DEVICE)
        
        import torch
        import torch.nn.functional as F
        with torch.no_grad():
            outputs = model(input_ids=input_ids, attention_mask=attention_mask)
            probs = F.softmax(outputs.logits, dim=1)
            confidence, pred_id = torch.max(probs, dim=1)
        
        label = ID2LABEL[pred_id.item()]
        conf = confidence.item()
        return label, conf, probs.squeeze().cpu().numpy()

def scan_code_by_lines(code: str, language: str, window_size: int = 5):
    lines = code.split('\n')
    issues = []
    seen_types = set()
    
    for i in range(0, len(lines), max(1, window_size // 2)):
        window_lines = lines[i:i + window_size]
        snippet = '\n'.join(window_lines)
        
        if len(snippet.strip()) < 5:
            continue
        
        label, confidence, _ = predict_snippet(snippet, language)
        
        if label == "CLEAN" or confidence < CONFIDENCE_THRESHOLD:
            continue
            
        if label in seen_types:
            continue
            
        seen_types.add(label)
        
        issue = Issue(
            type=label,
            severity=SEVERITY_MAP.get(label, "info"),
            confidence=round(confidence, 3),
            line=i + 1,
            message=f"{label.replace('_', ' ').title()} Detected",
            description="Potential security vulnerability identified by ML engine.",
            cwe=CWE_MAP.get(label, "CWE-000"),
            owasp=OWASP_MAP.get(label, "A00:2021"),
            fix="Review code logic and apply proper sanitization."
        )
        issues.append(issue)
        
    return issues

# ── API Endpoints ─────────────────────────────────────
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
            scan_time_ms=elapsed
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/ml/health")
async def health():
    return {
        "status": "ok",
        "mock_mode": MOCK_MODE,
        "device": str(DEVICE),
        "labels": len(ID2LABEL)
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)