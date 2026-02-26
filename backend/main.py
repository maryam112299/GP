import json
import logging
import sqlite3
from datetime import datetime, UTC
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from models import (
    AnalysisRequest,
    AnalysisResponse,
    SignupRequest,
    LoginRequest,
    AuthResponse,
    UserProfile,
    UpdateProfileRequest,
)
from analysis_service import analysis_service
from db import init_db, create_user, get_user_by_email, get_user_by_id, update_user_profile
from auth import hash_password, verify_password, create_access_token, decode_access_token

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Initialize FastAPI app
app = FastAPI(
    title="AI Agent Security Tester API",
    description="Security and vulnerability testing platform for AI agents and MCP servers",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_scheme = HTTPBearer(auto_error=False)


def _to_profile(user_doc) -> UserProfile:
    first_name = user_doc.get("first_name", "")
    last_name = user_doc.get("last_name", "")

    if (not first_name and not last_name) and user_doc.get("full_name"):
        name_parts = user_doc["full_name"].split(maxsplit=1)
        first_name = name_parts[0] if name_parts else ""
        last_name = name_parts[1] if len(name_parts) > 1 else ""

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


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    try:
        parsed_user_id = int(user_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")

    user = get_user_by_id(parsed_user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


@app.post("/api/auth/signup", response_model=AuthResponse)
async def signup(request: SignupRequest):
    email = request.email.lower().strip()
    created = create_user(
        email=email,
        full_name=request.full_name.strip(),
        password_hash=hash_password(request.password),
        created_at=datetime.now(UTC).isoformat(),
    )

    if created is None:
        raise HTTPException(status_code=409, detail="Email already registered")

    token = create_access_token(str(created["id"]), created["email"])
    return AuthResponse(access_token=token, user=_to_profile(created))


@app.post("/api/auth/login", response_model=AuthResponse)
async def login(request: LoginRequest):
    email = request.email.lower().strip()
    user = get_user_by_email(email)

    if not user or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_access_token(str(user["id"]), user["email"])
    return AuthResponse(access_token=token, user=_to_profile(user))


@app.get("/api/auth/me", response_model=UserProfile)
async def me(current_user=Depends(get_current_user)):
    return _to_profile(current_user)


@app.get("/api/profile", response_model=UserProfile)
async def get_profile(current_user=Depends(get_current_user)):
    return _to_profile(current_user)


@app.put("/api/profile", response_model=UserProfile)
async def edit_profile(request: UpdateProfileRequest, current_user=Depends(get_current_user)):
    first_name = request.first_name.strip()
    if not first_name:
        raise HTTPException(status_code=422, detail="First name is required")

    try:
        updated_user = update_user_profile(
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

    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")

    return _to_profile(updated_user)


@app.on_event("startup")
async def startup_event():
    init_db()

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "online",
        "service": "AI Agent Security Tester",
        "version": "1.0.0",
        "model": "mistral:latest"
    }

@app.post("/api/analyze", response_model=AnalysisResponse)
async def analyze_agent(request: AnalysisRequest, current_user=Depends(get_current_user)):
    """
    Analyzes an AI agent description for security vulnerabilities.
    
    Uses MAESTRO framework for architecture decomposition and 
    ATFAA framework for behavioral threat identification.
    """
    try:
        logging.info("=" * 60)
        logging.info("AI AGENT SECURITY SCANNER - RISK ANALYSIS")
        logging.info("=" * 60)
        logging.info(f"INPUT AGENT DESCRIPTION (user={current_user['email']}):\n{request.agent_description.strip()}")
        logging.info("-" * 60)
        
        # Perform analysis
        result = await analysis_service.analyze_agent(request.agent_description)
        
        # Save mission file
        with open("mission_file.json", "w") as f:
            f.write(result.model_dump_json(indent=2))
        
        logging.info("=" * 60)
        logging.info("ANALYSIS COMPLETE - Mission file saved")
        logging.info("=" * 60)
        
        return result
        
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

@app.get("/api/health")
async def health_check():
    """Detailed health check including model status"""
    try:
        # Test if model is loaded
        test_response = analysis_service.llm.invoke("test")
        return {
            "status": "healthy",
            "model": "mistral:latest",
            "model_loaded": True,
            "api_version": "1.0.0"
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "model": "mistral:latest",
            "model_loaded": False,
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    
    print("\n" + "=" * 60)
    print("AI AGENT SECURITY TESTER - Backend Server")
    print("=" * 60)
    print("Model: Mistral Latest")
    print("Frameworks: MAESTRO & ATFAA")
    print("=" * 60 + "\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
