"""
RakshakAI v2 — production FastAPI server.

Exposes:
    POST /v2/scan          — single-snippet analysis
    POST /v2/review        — diff review
    POST /v2/generate      — generate secure code from a prompt
    POST /v2/batch         — batch scan
    GET  /v2/health
    GET  /v2/version

The server is a thin wrapper around vLLM. v1's CPU classifier can be plugged
in as a fast-path prefilter: if v1 says "no vulnerability", the request is
returned in <50 ms without ever calling the LLM.

Run:
    uvicorn v2.deploy.server:app --host 0.0.0.0 --port 8080 --workers 1
"""
from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

log = logging.getLogger("rakshakai-v2")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ----- config (overridable via env) -----
MODEL_PATH = os.environ.get("RAKSHAK_V2_MODEL", "v2/outputs/merged/rakshakai-v2-bf16")
AWQ_PATH = os.environ.get("RAKSHAK_V2_AWQ", "v2/outputs/awq/rakshakai-v2-awq")
USE_AWQ = os.environ.get("RAKSHAK_V2_USE_AWQ", "1") == "1"
MAX_MODEL_LEN = int(os.environ.get("RAKSHAK_V2_MAX_LEN", "8192"))
GPU_MEM_UTIL = float(os.environ.get("RAKSHAK_V2_GPU_MEM", "0.85"))
ENABLE_V1_PREFILTER = os.environ.get("RAKSHAK_V2_V1_PREFILTER", "1") == "1"
TEMPERATURE = float(os.environ.get("RAKSHAK_V2_TEMPERATURE", "0.0"))
MAX_TOKENS = int(os.environ.get("RAKSHAK_V2_MAX_TOKENS", "1500"))


SYSTEM_PROMPT = (
    "You are RakshakAI v2, a security-specialized code analysis model. "
    "Respond as a single JSON object with the fields: vulnerability, cwe, "
    "severity, confidence, root_cause, attack_scenario, secure_fix, "
    "patched_code, references. No prose outside JSON."
)


# ----- request / response schemas -----
class ScanRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=200_000)
    language: str = Field("python")
    filename: str | None = None
    context: str | None = None  # optional surrounding code


class ReviewRequest(BaseModel):
    diff: str = Field(..., min_length=1, max_length=200_000)
    language: str = Field("python")
    filename: str | None = None


class GenerateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=10_000)
    language: str = Field("python")


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(..., min_length=1, max_length=64)


class Finding(BaseModel):
    vulnerability: str | None
    cwe: str | None
    severity: Literal["critical", "high", "medium", "low", "info", None] = None
    confidence: float = 0.0
    root_cause: str | None = None
    attack_scenario: str | None = None
    secure_fix: str | None = None
    patched_code: str | None = None
    references: list[str] = []


class ScanResponse(BaseModel):
    finding: Finding
    engine: str
    latency_ms: float
    v1_prefilter: dict | None = None


class VersionInfo(BaseModel):
    engine: str
    model_path: str
    awq: bool
    max_model_len: int
    v1_prefilter: bool


# ----- server state -----
class Server:
    def __init__(self) -> None:
        self.llm = None
        self.tok = None
        self.v1 = None
        self.use_awq = USE_AWQ and bool(AWQ_PATH) and os.path.isdir(AWQ_PATH)
        self.model_path = AWQ_PATH if self.use_awq else MODEL_PATH

    def load(self) -> None:
        log.info(f"loading vLLM engine on {self.model_path} (awq={self.use_awq})")
        from vllm import LLM
        from transformers import AutoTokenizer

        kwargs: dict[str, Any] = dict(
            model=self.model_path,
            dtype="bfloat16" if not self.use_awq else "float16",
            gpu_memory_utilization=GPU_MEM_UTIL,
            max_model_len=MAX_MODEL_LEN,
            enforce_eager=False,
            tensor_parallel_size=1,
        )
        if self.use_awq:
            kwargs["quantization"] = "awq"
        self.llm = LLM(**kwargs)
        self.tok = AutoTokenizer.from_pretrained(self.model_path, trust_remote_code=True)

        if ENABLE_V1_PREFILTER:
            try:
                from rakshakai.inference import RakshakInference
                self.v1 = RakshakInference()
                log.info("v1 prefilter enabled")
            except Exception as e:  # noqa: BLE001
                log.warning(f"v1 prefilter unavailable: {e}")
                self.v1 = None

    def generate(self, user_msg: str, max_tokens: int = MAX_TOKENS) -> tuple[dict, float]:
        from vllm import SamplingParams
        prompt = self.tok.apply_chat_template(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_msg},
            ],
            tokenize=False,
            add_generation_prompt=True,
        )
        sp = SamplingParams(temperature=TEMPERATURE, max_tokens=max_tokens)
        t0 = time.time()
        out = self.llm.generate(prompt, sp)
        dt = time.time() - t0
        text = out[0].outputs[0].text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if "\n" in text:
                text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = {"raw": text, "parse_error": True}
        return obj, dt


STATE = Server()


@asynccontextmanager
async def lifespan(app: FastAPI):
    STATE.load()
    yield
    STATE.llm = None


app = FastAPI(
    title="RakshakAI v2",
    version="2.0.0",
    description="Security-specialized coding LLM. Fine-tuned from Qwen2.5-Coder-7B-Instruct.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ----- routes -----
@app.get("/v2/health")
async def health() -> dict:
    return {"status": "ok", "engine": "vllm+qwen2.5-coder-7b+qlora", "v2": True}


@app.get("/v2/version", response_model=VersionInfo)
async def version() -> VersionInfo:
    return VersionInfo(
        engine="vllm",
        model_path=STATE.model_path,
        awq=STATE.use_awq,
        max_model_len=MAX_MODEL_LEN,
        v1_prefilter=STATE.v1 is not None,
    )


def _build_user_for_scan(req: ScanRequest) -> str:
    extra = f"\n\nContext:\n```\n{req.context}\n```" if req.context else ""
    return (
        f"```{req.language}\n{req.code}\n```{extra}\n\n"
        "Analyze this snippet. Identify any vulnerability, classify its CWE, "
        "explain the root cause, describe a realistic attack scenario, propose a "
        "secure fix, and provide the patched code. Respond as JSON only."
    )


def _normalize(obj: dict) -> Finding:
    return Finding(
        vulnerability=obj.get("vulnerability"),
        cwe=obj.get("cwe"),
        severity=obj.get("severity"),
        confidence=float(obj.get("confidence") or 0.0),
        root_cause=obj.get("root_cause"),
        attack_scenario=obj.get("attack_scenario"),
        secure_fix=obj.get("secure_fix"),
        patched_code=obj.get("patched_code"),
        references=list(obj.get("references") or []),
    )


@app.post("/v2/scan", response_model=ScanResponse)
async def scan(req: ScanRequest) -> ScanResponse:
    prefilter = None
    if STATE.v1 is not None:
        try:
            prefilter = STATE.v1.scan(req.code, req.language)
        except Exception as e:  # noqa: BLE001
            log.debug(f"v1 prefilter error: {e}")

    if prefilter and not prefilter.get("issues"):
        return ScanResponse(
            finding=Finding(
                vulnerability=None,
                cwe=None,
                severity=None,
                confidence=0.95,
                root_cause="v1 fast-path classifier: no indicators detected",
                attack_scenario=None,
                secure_fix=None,
                patched_code=None,
                references=[],
            ),
            engine="v1-prefilter",
            latency_ms=0.5,
            v1_prefilter=prefilter,
        )

    obj, dt = STATE.generate(_build_user_for_scan(req))
    return ScanResponse(
        finding=_normalize(obj),
        engine="v2-llm",
        latency_ms=dt * 1000,
        v1_prefilter=prefilter,
    )


@app.post("/v2/review", response_model=ScanResponse)
async def review(req: ReviewRequest) -> ScanResponse:
    user = (
        f"Review the following diff for security issues and produce a JSON security review.\n\n"
        f"```diff\n{req.diff}\n```"
    )
    obj, dt = STATE.generate(user)
    return ScanResponse(
        finding=_normalize(obj),
        engine="v2-llm",
        latency_ms=dt * 1000,
    )


@app.post("/v2/generate", response_model=ScanResponse)
async def generate_secure(req: GenerateRequest) -> ScanResponse:
    user = (
        f"Write a secure {req.language} implementation for the following requirement. "
        f"Follow security best practices. Output the code in a JSON object field "
        f"called `patched_code`.\n\nRequirement:\n{req.prompt}"
    )
    obj, dt = STATE.generate(user)
    # synthesize a Finding for the response
    return ScanResponse(
        finding=_normalize(obj),
        engine="v2-llm",
        latency_ms=dt * 1000,
    )


@app.post("/v2/batch")
async def batch_scan(req: BatchScanRequest) -> list[ScanResponse]:
    if not req.items:
        raise HTTPException(status_code=400, detail="empty batch")
    prompts = [_build_user_for_scan(it) for it in req.items]
    from vllm import SamplingParams
    sp = SamplingParams(temperature=TEMPERATURE, max_tokens=MAX_TOKENS)
    chat_inputs = [
        STATE.tok.apply_chat_template(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": p},
            ],
            tokenize=False,
            add_generation_prompt=True,
        )
        for p in prompts
    ]
    t0 = time.time()
    outs = STATE.llm.generate(chat_inputs, sp)
    dt_total = (time.time() - t0) * 1000
    per = dt_total / len(outs)
    responses: list[ScanResponse] = []
    for o in outs:
        text = o.outputs[0].text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if "\n" in text:
                text = text.split("\n", 1)[1]
            if text.endswith("```"):
                text = text[:-3]
        try:
            obj = json.loads(text)
        except json.JSONDecodeError:
            obj = {"raw": text, "parse_error": True}
        responses.append(
            ScanResponse(
                finding=_normalize(obj),
                engine="v2-llm",
                latency_ms=per,
            )
        )
    return responses


def main() -> None:
    uvicorn.run("v2.deploy.server:app", host="0.0.0.0", port=8080, workers=1, log_level="info")


if __name__ == "__main__":
    main()
