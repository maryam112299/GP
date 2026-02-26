# Project Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        USER BROWSER                         │
│                    http://localhost:3000                    │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ HTTP/REST
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    NEXT.JS FRONTEND                         │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Components:                                          │  │
│  │  • AgentInput.tsx    - User input interface          │  │
│  │  • ResultsDisplay.tsx - Vulnerability visualization  │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Features:                                            │  │
│  │  • Glass morphism UI                                 │  │
│  │  • Real-time animations                              │  │
│  │  • JSON export                                       │  │
│  │  • Syntax highlighting                               │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ API Calls
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   FASTAPI BACKEND                           │
│                 http://localhost:8000                       │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Endpoints:                                           │  │
│  │  • POST /api/analyze  - Main analysis endpoint       │  │
│  │  • GET  /api/health   - Health check                 │  │
│  │  • GET  /docs         - Swagger UI                   │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Analysis Service:                                    │  │
│  │  • MAESTRO Framework - Architecture decomposition    │  │
│  │  • ATFAA Framework   - Threat identification         │  │
│  │  • LangChain         - LLM orchestration             │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ LLM API
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      OLLAMA SERVICE                         │
│                         (Local)                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Model: Mistral Latest                                │  │
│  │  • Structured output generation                       │  │
│  │  • JSON formatting                                    │  │
│  │  • Risk analysis                                      │  │
│  │  • Attack vector identification                       │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

```
1. USER INPUT
   └─> Agent Description (text)
       │
2. FRONTEND PROCESSING
   └─> Validation & UI feedback
       │
3. API REQUEST
   └─> POST to /api/analyze
       │
4. BACKEND ANALYSIS
   ├─> Parse agent description
   ├─> Apply MAESTRO framework
   ├─> Apply ATFAA framework
   └─> Generate structured prompt
       │
5. LLM PROCESSING
   └─> Mistral analyzes security risks
       └─> Returns structured JSON
           │
6. RESPONSE FORMATTING
   ├─> agent_id
   ├─> risk_summary
   └─> attack_plan[]
       ├─> vulnerability_type
       ├─> priority (CRITICAL/HIGH/MEDIUM/LOW)
       ├─> maestro_layer
       ├─> atfaa_domain
       ├─> injection_type
       ├─> target_asset
       ├─> exploit_strategy
       └─> adversarial_objective
           │
7. FRONTEND DISPLAY
   ├─> Priority badges
   ├─> Color-coded cards
   ├─> JSON viewer
   └─> Export functionality
```

## Technology Stack

### Frontend Technologies
- **Next.js 14**: React framework with App Router
- **TypeScript**: Type safety and IntelliSense
- **Tailwind CSS**: Utility-first styling
- **Framer Motion**: Animation library
- **Lucide React**: Icon library
- **React Syntax Highlighter**: Code display
- **React Hot Toast**: Notifications

### Backend Technologies
- **FastAPI**: Modern Python web framework
- **Pydantic**: Data validation
- **LangChain-Ollama**: LLM integration
- **Uvicorn**: ASGI server

### AI/ML Stack
- **Ollama**: Local LLM runtime
- **Mistral**: Large language model
- **MAESTRO**: Security framework
- **ATFAA**: Threat modeling framework

## File Structure

```
agent-security-tester/
│
├── Frontend (Next.js)
│   ├── app/
│   │   ├── layout.tsx        # Root layout with providers
│   │   ├── page.tsx          # Main application page
│   │   └── globals.css       # Global styles & animations
│   ├── components/
│   │   ├── AgentInput.tsx    # Input form component
│   │   └── ResultsDisplay.tsx # Results visualization
│   ├── types/
│   │   └── index.ts          # TypeScript definitions
│   ├── package.json          # Node dependencies
│   ├── tsconfig.json         # TypeScript config
│   ├── tailwind.config.js    # Tailwind configuration
│   └── next.config.js        # Next.js configuration
│
├── Backend (FastAPI)
│   ├── main.py               # FastAPI application
│   ├── models.py             # Pydantic models
│   ├── analysis_service.py   # Core analysis logic
│   ├── requirements.txt      # Python dependencies
│   └── __init__.py           # Package initialization
│
├── Documentation
│   ├── README.md             # Complete documentation
│   ├── SETUP_GUIDE.md        # Quick start guide
│   └── ARCHITECTURE.md       # This file
│
├── Scripts (Windows)
│   ├── start-all.bat         # Start both servers
│   ├── start-frontend.bat    # Start frontend only
│   └── start-backend.bat     # Start backend only
│
└── Configuration
    ├── .gitignore            # Git ignore rules
    ├── .env.example          # Environment template
    └── .eslintrc.json        # ESLint configuration
```

## Security Frameworks

### MAESTRO Framework Layers
1. **Foundation Model**: Base LLM vulnerabilities
2. **Data Operations**: Data handling security
3. **Agent Framework**: Agent-specific risks
4. **Infrastructure**: System-level security
5. **Security & Compliance**: Policy violations
6. **Agent Ecosystem**: Inter-agent threats

### ATFAA Threat Domains
1. **Cognitive Architecture**: Goal drift, manipulation
2. **Temporal Persistence**: Memory poisoning
3. **Operational Execution**: Tool abuse, privilege escalation
4. **Trust Boundary Violation**: Input injection, data exfiltration
5. **Governance Circumvention**: Policy bypass

## API Endpoints

### POST /api/analyze
**Request:**
```json
{
  "agent_description": "string"
}
```

**Response:**
```json
{
  "agent_id": "string",
  "risk_summary": "string",
  "attack_plan": [
    {
      "vulnerability_type": "string",
      "priority": "CRITICAL|HIGH|MEDIUM|LOW",
      "maestro_layer": "string",
      "atfaa_domain": "string",
      "injection_type": "string",
      "target_asset": "string",
      "exploit_strategy": "string",
      "adversarial_objective": "string"
    }
  ]
}
```

### GET /api/health
**Response:**
```json
{
  "status": "healthy",
  "model": "mistral:latest",
  "model_loaded": true,
  "api_version": "1.0.0"
}
```

## Extension Points

### Adding New Analysis Types
1. Add model to `backend/models.py`
2. Implement service in `backend/analysis_service.py`
3. Create endpoint in `backend/main.py`
4. Add TypeScript types in `types/index.ts`
5. Create UI component in `components/`
6. Integrate in `app/page.tsx`

### Customizing UI Theme
1. Edit `tailwind.config.js` for colors
2. Modify `app/globals.css` for animations
3. Update components for new design

### Integrating Different Models
1. Update Ollama model in `backend/analysis_service.py`
2. Adjust prompt engineering as needed
3. Test structured output compatibility

## Performance Considerations

- **Frontend**: Next.js optimizes bundles automatically
- **Backend**: FastAPI runs async for better throughput
- **Model**: Mistral kept in memory with `keep_alive=-1`
- **CORS**: Configured for localhost development

## Security Notes

- **Development Mode**: CORS allows localhost
- **Production**: Implement authentication, HTTPS, rate limiting
- **API Keys**: Use environment variables
- **Input Validation**: Pydantic handles backend validation
- **Output Sanitization**: React handles XSS prevention

---

**Architecture designed for extensibility and maintainability**
