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
from fastapi import FastAPI, HTTPException, Depends, Request, Response, status
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
)
from prompts import build_quick_prompt, build_expert_prompt
from analysis_service import analysis_service
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
