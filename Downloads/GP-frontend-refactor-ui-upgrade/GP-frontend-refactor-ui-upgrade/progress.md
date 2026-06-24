# AI Security Platform — Progress Log

> Last updated: 2026-04-06  
> Status: **Phase 1 (Backend) ✅ | Phase 2 (Frontend) ✅ | Verification ✅**

---

## What Changed & Why

### Backend

| File | Change | Rationale |
|---|---|---|
| `models.py` | Added `AnalysisMode`, `VulnScope`, `ExpertAnalysisRequest`, `QuickAnalysisRequest`; updated `AnalysisRequest`; added `mode` to `ScanRecord` | Required to support dual-mode analysis and persist mode per scan |
| `prompts.py` | **NEW** — `build_quick_prompt()` and `build_expert_prompt()` | Separates prompt engineering from service logic; easier iteration per mode |
| `analysis_service.py` | Refactored `AnalysisService` to own its `llm` instance; wrapped sync LLM call with `asyncio.run_in_executor` | Prevented blocking the event loop; removed module-level singleton side-effects |
| `main.py` | Replaced deprecated `@app.on_event` with `lifespan`; `/api/analyze` now mode-aware; `/api/health` no longer invokes LLM; added `/api/health/model` | Modernised FastAPI lifecycle; fixed LLM invocation blocking health check |
| `db.py` | Added `mode` column to `analyses` table via `_ensure_analysis_columns`; extracted `_USER_SELECT` constant | Migration-safe; avoids column repetition |

### Frontend

| File | Change | Rationale |
|---|---|---|
| `lib/constants.ts` | **NEW** — `API_BASE` | Single source of truth for API URL |
| `lib/api.ts` | **NEW** — `authApi`, `profileApi`, `scansApi`, `analysisApi` | Centralised typed API client; removes scattered fetch calls from pages |
| `types/index.ts` | Added `AnalysisMode`, `VulnScope`, `ExpertConfig`, `UserProfile` export; updated `ScanRecord` with `mode` | Eliminates local type duplication across pages |
| `app/globals.css` | Full overhaul: CSS design tokens, Outfit + JetBrains Mono fonts, glass/input/button/badge systems, keyframe animations | Premium design system instead of ad-hoc Tailwind utilities |
| `app/layout.tsx` | Outfit + JetBrains Mono via `next/font`; enriched metadata / OpenGraph | Proper font loading; better SEO |
| `components/ui/Header.tsx` | **NEW** — shared header component | Eliminates duplication between `page.tsx` and `profile/page.tsx` |
| `components/auth/AuthModal.tsx` | **NEW** — polished login/signup card | Replaces bare inline form; adds labels, icons, password toggle, tab animation |
| `components/analysis/ModeSelector.tsx` | **NEW** — Quick / Expert animated toggle | Enables mode selection with descriptions |
| `components/analysis/QuickAnalysis.tsx` | **NEW** — single-field quick form | Minimal input path; example presets |
| `components/analysis/ExpertAnalysis.tsx` | **NEW** — 4-section expert form | Full structured input: identity, tools, scope checkboxes, architecture notes |
| `components/ResultsDisplay.tsx` | Severity bar, collapsible attack cards, mode badge, JSON toggle | Richer results; avoids rendering full JSON by default |
| `app/page.tsx` | Slim (~170 lines): delegates to all above components; `useCallback` guards | Clear separation of concerns; performance-safe closures |
| `app/profile/page.tsx` | Uses `types/index.ts` + `lib/api.ts`; mode badge on scans; no redundant re-fetch | No duplication; cleaner scan history cards |

---

## Architecture Overview

```
frontend/
  app/
    page.tsx            ← auth gate + mode toggle + results
    profile/page.tsx    ← profile edit + scan history
    layout.tsx          ← fonts, metadata
    globals.css         ← full design system
  components/
    ui/Header.tsx       ← shared header
    auth/AuthModal.tsx  ← login / signup card
    analysis/
      ModeSelector.tsx  ← Quick | Expert toggle
      QuickAnalysis.tsx ← single-field form
      ExpertAnalysis.tsx← structured multi-section form
    ResultsDisplay.tsx  ← severity bar, collapsible cards
  lib/
    constants.ts        ← API_BASE
    api.ts              ← typed API client
  types/index.ts        ← all shared types

backend/
  main.py               ← lifespan, mode-aware endpoints
  models.py             ← Pydantic models + enums
  prompts.py            ← prompt factory (Quick / Expert)
  analysis_service.py   ← async-safe LLM service
  db.py                 ← SQLite with migration guards
  auth.py               ← JWT + bcrypt
  scoring.py            ← CVSS-style severity scoring
```

---

## Two Modes Explained

### Quick Mode
- Frontend: single textarea → `QuickAnalysisRequest`
- Backend: `build_quick_prompt(description)` → 3–5 attack paths
- Payload: `{ mode: "quick", agent_description: "..." }`

### Expert Mode
- Frontend: 4-section form → `ExpertAnalysisRequest`
- Backend: `build_expert_prompt(name, mission, tools, sources, notes, scope)` → 5–8 attack paths
- Payload: `{ mode: "expert", agent_name, mission, tools[], data_sources[], architecture_notes, scope[], agent_description }`

---

## Running the Project

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend
cd ..
npm install
npm run dev
```

---

## Known Limitations / Future Work

- [ ] Rate limiting on `/api/analyze` (Mistral can be slow)
- [ ] JWT refresh token flow
- [ ] Streaming LLM output for real-time UI updates
- [ ] Export scan report as PDF
- [ ] Scan comparison view (diff between two runs)
- [ ] MCP-specific attack modules
