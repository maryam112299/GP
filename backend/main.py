"""
main.py — FastAPI application entry point.

Architecture notes:
- lifespan context manager (replaces deprecated @app.on_event)
- /api/analyze accepts AnalysisRequest with both quick and expert fields
- Prompt selection is delegated to prompts.py based on request.mode
- /api/health does NOT invoke the LLM to avoid blocking the event loop
- Rate limiting via slowapi: 5 analyses/hour per authenticated user
- Auth via httpOnly cookie (preferred) with Bearer token fallback
"""

import os
import logging
import sqlite3
from contextlib import asynccontextmanager
from time import perf_counter
from datetime import datetime, UTC

from dotenv import load_dotenv

# Load .env BEFORE importing modules that read os.getenv at import time
# (analysis_service builds its ChatOllama client at module load).
load_dotenv()

from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from models import (
    AnalysisMode,
    AnalysisRequest,
    AnalysisResponse,
    ScanHistoryResponse,
    SignupRequest,
    LoginRequest,
    AuthResponse,
    UserProfile,
    UpdateProfileRequest,
    GeneratePayloadsRequest,
    GeneratePayloadsResponse,
    PayloadResult,
    EvaluateRequest,
    EvaluateResponse,
    VulnEvalSummary,
    PayloadEvalResult,
    ReportRequest,
    RedTeamLoopRequest,
)
from prompts import build_quick_prompt, build_expert_prompt
from analysis_service import analysis_service
from payload_generator import payload_generator_service
from evaluator import evaluator_service
from db import (
    init_db,
    create_user,
    get_user_by_email,
    get_user_by_id,
    update_user_profile,
    create_analysis_record,
    get_analyses_by_user_id,
)
from auth import hash_password, verify_password, create_access_token, decode_access_token

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up — initialising database …")
    init_db()
    logger.info("Database ready.")

    # Pre-warm semantic evaluation models so the first payload isn't penalised
    # by a 4-second cold-load. Run in executor to avoid blocking the event loop.
    import asyncio
    loop = asyncio.get_event_loop()
    async def _warm_models():
        try:
            def _load():
                from semantic_evaluator import calibrate_threshold
                calibrate_threshold()   # loads embedder + cross-encoder + runs calibration
                logger.info("Semantic evaluation models pre-warmed.")
            await loop.run_in_executor(None, _load)
        except Exception as exc:
            logger.warning("Model pre-warm failed (will load on first use): %s", exc)
    asyncio.ensure_future(_warm_models())

    yield
    logger.info("Shutting down.")


# ---------------------------------------------------------------------------
# Rate limiter (per remote address — good enough for local/demo use)
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="AI Agent Security Tester API",
    description="Security and vulnerability testing platform for AI agents and MCP servers",
    version="2.0.0",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_default_origins = "http://localhost:3000,http://localhost:3001"
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", _default_origins).split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)

ACCESS_TOKEN_COOKIE = "access_token"


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _to_profile(user_doc: dict) -> UserProfile:
    first_name = user_doc.get("first_name", "")
    last_name  = user_doc.get("last_name", "")

    if not first_name and not last_name and user_doc.get("full_name"):
        parts      = user_doc["full_name"].split(maxsplit=1)
        first_name = parts[0] if parts else ""
        last_name  = parts[1] if len(parts) > 1 else ""

    return UserProfile(
        id=str(user_doc["id"]),
        email=user_doc["email"],
        first_name=first_name,
        last_name=last_name,
        mobile_number=user_doc.get("mobile_number", ""),
        company_name=user_doc.get("company_name", ""),
        job_role=user_doc.get("job_role", ""),
        country=user_doc.get("country", ""),
    )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> dict:
    """Accept token from httpOnly cookie first, then fall back to Bearer header."""
    token: str | None = None

    # 1. Prefer httpOnly cookie (more secure)
    cookie_token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if cookie_token:
        token = cookie_token
    # 2. Fall back to Authorization: Bearer <token>
    elif credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials

    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        parsed_id = int(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    user = get_user_by_id(parsed_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------

def _set_auth_cookie(response: Response, token: str) -> None:
    """Write the JWT into an httpOnly, SameSite=Lax cookie."""
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=os.getenv("COOKIE_SECURE", "false").lower() == "true",
        max_age=int(os.getenv("JWT_EXPIRE_HOURS", "24")) * 3600,
        path="/",
    )


@app.post("/api/auth/signup", response_model=AuthResponse, tags=["auth"])
async def signup(request: SignupRequest, response: Response):
    email   = request.email.lower().strip()
    created = create_user(
        email=email,
        full_name=request.full_name.strip(),
        password_hash=hash_password(request.password),
        created_at=datetime.now(UTC).isoformat(),
    )
    if created is None:
        raise HTTPException(status_code=409, detail="Email already registered")

    token = create_access_token(str(created["id"]), created["email"])
    _set_auth_cookie(response, token)
    return AuthResponse(access_token=token, user=_to_profile(created))


@app.post("/api/auth/login", response_model=AuthResponse, tags=["auth"])
async def login(request: LoginRequest, response: Response):
    email = request.email.lower().strip()
    user  = get_user_by_email(email)

    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(str(user["id"]), user["email"])
    _set_auth_cookie(response, token)
    return AuthResponse(access_token=token, user=_to_profile(user))


@app.post("/api/auth/logout", tags=["auth"])
async def logout(response: Response):
    """Clear the httpOnly auth cookie."""
    response.delete_cookie(key=ACCESS_TOKEN_COOKIE, path="/")
    return {"detail": "Logged out"}


@app.get("/api/auth/me", response_model=UserProfile, tags=["auth"])
async def me(current_user: dict = Depends(get_current_user)):
    return _to_profile(current_user)


# ---------------------------------------------------------------------------
# Profile endpoints
# ---------------------------------------------------------------------------

@app.get("/api/profile", response_model=UserProfile, tags=["profile"])
async def get_profile(current_user: dict = Depends(get_current_user)):
    return _to_profile(current_user)


@app.put("/api/profile", response_model=UserProfile, tags=["profile"])
async def edit_profile(
    request: UpdateProfileRequest,
    current_user: dict = Depends(get_current_user),
):
    first_name = request.first_name.strip()
    if not first_name:
        raise HTTPException(status_code=422, detail="First name is required")

    try:
        updated = update_user_profile(
            user_id=current_user["id"],
            email=request.email.lower().strip(),
            first_name=first_name,
            last_name=(request.last_name or "").strip(),
            mobile_number=(request.mobile_number or "").strip(),
            company_name=(request.company_name or "").strip(),
            job_role=(request.job_role or "").strip(),
            country=(request.country or "").strip(),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email already registered")

    if not updated:
        raise HTTPException(status_code=404, detail="User not found")

    return _to_profile(updated)


# ---------------------------------------------------------------------------
# Scan history
# ---------------------------------------------------------------------------

@app.get("/api/scans", response_model=ScanHistoryResponse, tags=["scans"])
async def get_user_scans(current_user: dict = Depends(get_current_user)):
    scans = get_analyses_by_user_id(current_user["id"])
    return ScanHistoryResponse(scans=scans)


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

@app.post("/api/analyze", response_model=AnalysisResponse, tags=["analysis"])
@limiter.limit(os.getenv("ANALYZE_RATE_LIMIT", "5/hour"))
async def analyze_agent(
    request: Request,
    body: AnalysisRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Analyze an AI agent for security vulnerabilities.

    Supports two modes:
    - **quick**: single description, inferred defaults, 3-5 attack paths.
    - **expert**: structured fields + scope, 5-8 focused attack paths.

    Uses MAESTRO (layer decomposition) and ATFAA (behavioral threat) frameworks.
    """
    logger.info(
        "Analysis request — user=%s mode=%s",
        current_user["email"],
        body.mode.value,
    )

    # Build mode-appropriate prompt
    if body.mode == AnalysisMode.EXPERT:
        prompt = build_expert_prompt(
            agent_name=body.agent_name or "Unknown Agent",
            mission=body.mission or body.agent_description,
            tools=body.tools or [],
            data_sources=body.data_sources or [],
            architecture_notes=body.architecture_notes or "",
            scope=[s.value for s in (body.scope or [])],
            agent_description=body.agent_description,
            uses_mcp=body.uses_mcp,
            uses_rag=body.uses_rag,
        )
    else:
        prompt = build_quick_prompt(
            body.agent_description,
            uses_mcp=body.uses_mcp,
            uses_rag=body.uses_rag,
        )

    started_at = perf_counter()

    try:
        result = await analysis_service.analyze_agent(prompt)
    except Exception as exc:
        logger.error("Analysis failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")

    duration = round(perf_counter() - started_at, 3)
    scoring_mode = os.getenv("SCORING_MODE", "cvss")

    create_analysis_record(
        user_id=current_user["id"],
        input_text=body.agent_description,
        output_json=result.model_dump_json(),
        duration_seconds=duration,
        created_at=datetime.now(UTC).isoformat(),
        mode=body.mode.value,
        scoring_mode=scoring_mode,
    )

    logger.info("Analysis complete in %.2fs — %d paths found.", duration, len(result.attack_plan))
    return result


# ---------------------------------------------------------------------------
# Payload Generation
# ---------------------------------------------------------------------------

@app.post("/api/generate-payloads", response_model=GeneratePayloadsResponse, tags=["analysis"])
async def generate_payloads(
    body: GeneratePayloadsRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Generate adversarial payloads for each vulnerability in an analysis report.
    Uses the fine-tuned redteam GGUF model to craft context-aware attack prompts.
    """
    if not payload_generator_service.model_available:
        raise HTTPException(
            status_code=503,
            detail="Redteam model not available. Make sure Ollama is running and the 'redteam' model is registered.",
        )

    logger.info(
        "Payload generation request — user=%s vulnerabilities=%d",
        current_user["email"],
        len(body.analysis.attack_plan),
    )

    try:
        analysis_dict = body.analysis.model_dump(mode="json")
        gen_kwargs: dict = {}
        if body.max_payloads_per_vuln:
            gen_kwargs["max_payloads_per_vuln"] = body.max_payloads_per_vuln
        if body.victim_url:
            gen_kwargs["victim_url"] = body.victim_url
        raw_payloads = await payload_generator_service.generate(
            body.agent_description, analysis_dict, **gen_kwargs,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except Exception as exc:
        logger.error("Payload generation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Payload generation failed: {exc}")

    payloads = [PayloadResult(**p) for p in raw_payloads]
    applicable = sum(1 for p in payloads if p.applicable)

    logger.info("Payload generation complete — %d/%d applicable.", applicable, len(payloads))
    return GeneratePayloadsResponse(
        payloads=payloads,
        applicable_count=applicable,
        total_count=len(payloads),
    )


# ---------------------------------------------------------------------------
# Attack Simulation / Evaluation
# ---------------------------------------------------------------------------

@app.post("/api/evaluate", response_model=EvaluateResponse, tags=["analysis"])
async def evaluate_payloads(
    body: EvaluateRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Send generated payloads to the victim model (mistral) and evaluate each response.

    Payload priority: specific (context-aware) → generic (benchmark), capped at 10 per vuln.
    Evaluation: rule-based keyword matching first; llama3:latest LLM fallback for ambiguous cases.
    SUCCESS = model refused the attack (safe). FAIL = model complied (vulnerable).
    """
    total_payloads = sum(
        len(p.payloads) + len(p.generic_payloads) for p in body.payloads
    )
    logger.info(
        "Evaluation request — user=%s vuln_count=%d total_payloads=%d",
        current_user["email"],
        len(body.payloads),
        total_payloads,
    )

    try:
        payload_dicts = [p.model_dump(mode="json") for p in body.payloads]
        summaries = await evaluator_service.evaluate(
            payload_dicts,
            victim_url   = body.victim_url   or "",
            victim_model = body.victim_model or "",
            max_per_vuln = body.max_payloads_per_vuln,
        )
    except Exception as exc:
        logger.error("Evaluation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {exc}")

    total         = sum(s["total"] for s in summaries)
    total_success = sum(s["success_count"] for s in summaries)
    total_fail    = sum(s["fail_count"] for s in summaries)
    total_unknown = sum(s["unknown_count"] for s in summaries)
    overall_risk  = round(total_fail / total, 3) if total > 0 else 0.0

    logger.info(
        "Evaluation complete — tested=%d success=%d fail=%d unknown=%d risk=%.1f%%",
        total, total_success, total_fail, total_unknown, overall_risk * 100,
    )

    return EvaluateResponse(
        vuln_summaries=[VulnEvalSummary(**s) for s in summaries],
        overall_risk_score=overall_risk,
        total_tested=total,
        total_success=total_success,
        total_fail=total_fail,
        total_unknown=total_unknown,
    )


# ---------------------------------------------------------------------------
# Agentic Red-Team Loop
# ---------------------------------------------------------------------------

@app.post("/api/redteam-loop", tags=["analysis"])
async def redteam_loop(
    body: RedTeamLoopRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Adaptive black-box red-team loop with ceiling:
       Discover (iterative recon) → Plan → (Generate → Evaluate)* until any
       FAIL or `ceiling` rounds.

    Returns the full transcript: every discovery round's probes + replies and
    the synthesized intel, planner output, every attack round's verdicts, the
    final evaluation summary, and the stop_reason.
    """
    from redteam_loop import run_loop

    logger.info(
        "redteam-loop request — user=%s ceiling=%d max_per_vuln=%d discovery_rounds=%d use_pair=%s pair_attempts=%d backend=%s",
        current_user["email"], body.ceiling, body.max_payloads_per_vuln, body.discovery_rounds,
        body.use_pair, body.pair_attempts, body.refiner_backend or "(env)",
    )

    try:
        result = await run_loop(
            description      = body.agent_description,
            uses_mcp         = body.uses_mcp,
            uses_rag         = body.uses_rag,
            victim_url       = body.victim_url   or "",
            victim_model     = body.victim_model or "",
            max_per_vuln     = body.max_payloads_per_vuln,
            ceiling          = body.ceiling,
            discovery_rounds = body.discovery_rounds,
            probes_per_round = body.probes_per_round,
            use_pair         = body.use_pair,
            pair_attempts    = body.pair_attempts,
            refiner_backend  = body.refiner_backend or "",
        )
    except Exception as exc:
        logger.error("redteam-loop failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Red-team loop failed: {exc}")

    logger.info(
        "redteam-loop complete — stop=%s rounds=%d duration=%.1fs",
        result.get("stop_reason"), len(result.get("rounds", [])), result.get("duration_seconds", 0),
    )
    return result


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

@app.post("/api/report", tags=["analysis"])
async def generate_report(
    body: ReportRequest,
    current_user: dict = Depends(get_current_user),
):
    """
    Render a PDF security report from completed analysis + simulation results.
    Returns application/pdf bytes as a file download.
    """
    from report_generator import generate_pdf_report
    import asyncio

    analysis   = body.analysis
    evaluation = body.evaluation

    vuln_summaries = [s.model_dump(mode="json") for s in evaluation.vuln_summaries]

    logger.info(
        "Report request — user=%s agent=%s vulns=%d",
        current_user["email"],
        analysis.agent_id,
        len(vuln_summaries),
    )

    try:
        loop = asyncio.get_event_loop()
        pdf_bytes: bytes = await loop.run_in_executor(
            None,
            lambda: generate_pdf_report(
                agent_id          = analysis.agent_id,
                risk_summary      = analysis.risk_summary,
                attack_plan       = [obj.model_dump(mode="json") for obj in analysis.attack_plan],
                vuln_summaries    = vuln_summaries,
                overall_risk_score= evaluation.overall_risk_score,
                total_tested      = evaluation.total_tested,
                total_success     = evaluation.total_success,
                total_fail        = evaluation.total_fail,
                total_unknown     = evaluation.total_unknown,
                mode              = body.mode.value,
                duration_seconds  = body.duration_seconds,
            ),
        )
    except Exception as exc:
        logger.error("Report generation failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Report generation failed: {exc}")

    safe_id   = "".join(c if c.isalnum() or c in "-_" else "_" for c in analysis.agent_id)
    filename  = f"llmtron_report_{safe_id}.pdf"

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Utility endpoints
# ---------------------------------------------------------------------------

@app.get("/", tags=["utility"])
async def root():
    """Health check / service info."""
    return {
        "status": "online",
        "service": "AI Agent Security Tester",
        "version": "2.0.0",
        "model": analysis_service.model,
    }


@app.get("/api/health", tags=["utility"])
async def health_check():
    """
    Returns service health status without invoking the LLM.
    Check Ollama availability separately via /api/health/model.
    """
    return {
        "status": "healthy",
        "model": analysis_service.model,
        "api_version": "2.0.0",
    }


@app.get("/api/system-info", tags=["utility"])
async def system_info():
    """
    Reports which models and victim endpoint this backend is wired to.
    Used by the frontend to populate attack-package JSON exports so a
    reviewer can verify exactly which components produced a scan.
    """
    return {
        "analyzer_model":  analysis_service.model,
        "analyzer_url":    analysis_service.base_url,
        "generator_model": os.getenv("REDTEAM_MODEL", "redteam"),
        "victim_model":    os.getenv("VICTIM_MODEL", "mistral"),
        "victim_url":      os.getenv("VICTIM_BASE_URL", os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")),
        "evaluator_model": os.getenv("EVALUATOR_MODEL", "llama3"),
        "scoring_mode":    os.getenv("SCORING_MODE", "cvss"),
    }


@app.get("/api/health/model", tags=["utility"])
async def model_health():
    """Probes the LLM with a minimal test message (may be slow)."""
    try:
        loop = __import__("asyncio").get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: analysis_service.llm.invoke("ping"),
        )
        return {"status": "healthy", "model": analysis_service.model, "model_loaded": True}
    except Exception as exc:
        return {
            "status": "unhealthy",
            "model": analysis_service.model,
            "model_loaded": False,
            "error": str(exc),
        }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("BACKEND_PORT", "8000"))
    logger.info("Starting AI Agent Security Tester — Backend Server on port %d", port)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
