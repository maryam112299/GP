# UI Upgrade Plan — AI Agent Security Tester

> **Living document.** This plan is updated as each phase completes. Check the **Progress Log** at the bottom and the **Status** field on each phase for the current state.
>
> **Last updated:** 2026-06-23 · **Overall status:** 🟡 In progress (5 / 7 phases complete)

---

## 1. Context & Goal

Upgrade the existing Next.js frontend (`frontend/`) to match the new Claude Design handoff in
`ui-modernization-project/project/Analysis Workspace.dc.html` (the **sidebar** primary design),
while **preserving all existing functionality** (auth, quick/expert analysis, adaptive black-box
loop, payload generation, evaluation, scan history).

The redesign is a **theme reversal + structural reshape**, not a from-scratch rebuild. We keep the
React/Next architecture, API layer (`lib/api.ts`), and types (`types/index.ts`) untouched, and
re-skin + re-shell the presentation layer.

### Source of truth
- **Primary design:** `ui-modernization-project/project/Analysis Workspace.dc.html` (sidebar shell, fully interactive).
- **Layout explorations (reference only):** `Analysis Workspace v2.dc.html` (Frames D/E/F — not chosen).
- **Written brief:** `UI_DESIGN_BRIEF.md` (note: its *dark/green* palette is **superseded** by the new *light/indigo* design — see §4).

---

## 2. Locked Decisions

| # | Decision | Choice |
|---|----------|--------|
| D1 | Workspace layout | **Sidebar shell** (264px left sidebar + breadcrumb bar + phased workspace) |
| D2 | Auth / landing / profile | **Keep as-is for now.** Redesign workspace/dashboard/settings first; restyle auth/landing/profile in a later phase (Phase 8, deferred) |
| D3 | Theme | **Light + indigo** (`#f1f5f9` bg, `#4f46e5` accent) — supersedes the old dark/green theme |
| D4 | Tech | Stay on Next.js 16 + React 18 + Tailwind 3 + Framer Motion + lucide-react. No new core deps |

---

## 3. Current → Target Gap

| Aspect | Current (`frontend/`) | Target (new design) |
|--------|----------------------|---------------------|
| Theme | Dark `#080c12`, green `#06d6a0`, glass morphism, animated blobs | Light `#f1f5f9`, white cards, indigo `#4f46e5`, soft shadows |
| Shell | Top `Header` nav, single centered `max-w-4xl` column | 264px **left sidebar** + 56px breadcrumb bar + fluid main |
| Navigation | Home page + `/profile` route | In-app views: **Workspace / Dashboard / Settings** (sidebar nav) |
| Workspace | Mode selector + form, then loading overlay, then results stacked below | Phased: **input** (centered) → **analyzing** (checklist) → **results** (form sticks left 360px, results right) |
| Mode select | `ModeSelector` cards | Quick/Expert **segmented tab** toggle inside the form card |
| Integrations | Checkboxes | **Toggle-switch rows** (MCP / RAG) |
| Results | `ResultsDisplay` (dark) | Conic-gradient **risk gauge** + **severity breakdown bars** + **expandable vuln cards** (payload dark block + green mitigation block) |
| History | `/profile` scan list | **Recent Sessions** in sidebar + **Dashboard** stat cards |
| Fonts | Outfit + JetBrains Mono | Outfit + JetBrains Mono ✅ (unchanged) |

---

## 4. Design Token Mapping (old → new)

Drives Phase 0. Values extracted directly from the primary design file.

| Token | Old (dark) | New (light/indigo) |
|-------|-----------|--------------------|
| `bg-base` | `#080c12` | `#f1f5f9` |
| `bg-surface` (cards) | `#0d1117` | `#ffffff` |
| `bg-subtle` (inputs) | `#161b24` | `#fafbfc` |
| `border` | `rgba(255,255,255,.07)` | `#e5e7eb` |
| `accent` | `#06d6a0` (green) | `#4f46e5` (indigo); hover `#4338ca` |
| `accent-soft` (bg) | — | `#eef2ff`; border `#c7d2fe`; text `#3730a3` |
| `text-primary` | `#f0f6fc` | `#0f172a` |
| `text-secondary` | `#8b949e` | `#64748b` |
| `text-muted` | `#484f58` | `#94a3b8` |
| `critical` | `#f85149` | `#dc2626` (bg `#fef2f2`, bd `#fecaca`) |
| `high` | `#fb8c00` | `#ea580c` (bg `#fff7ed`, bd `#fed7aa`) |
| `medium` | `#f0c000` | `#ca8a04` (bg `#fefce8`, bd `#fde68a`) |
| `low` | `#58a6ff` | `#2563eb` (bg `#eff6ff`, bd `#bfdbfe`) |
| `maestro pill` | — | text `#7c3aed`, bg `#f5f3ff` |
| `atfaa pill` | — | text `#0891b2`, bg `#ecfeff` |
| `success` (mitigation) | — | text `#15803d`, bg `#f0fdf4`, bd `#bbf7d0` |
| Risk bands | — | ≥70 HIGH `#ea580c` · ≥40 MEDIUM `#ca8a04` · else LOW `#16a34a` |
| Radii | 6/10/14/20 | 8/10/12/14/16 (cards 14–16, inputs 10) |
| Scrollbar thumb | green | `#d4d8de` |
| Animations | float/glow/shimmer | `fadeUp`, `spin`, `barpulse` |

---

## 5. Phases

> Status legend: ⬜ Not started · 🟡 In progress · ✅ Done · ⏸️ Deferred

---

### Phase 0 — Design foundation (tokens & theme) ✅
**Goal:** Flip the global design system from dark/green to light/indigo so every later phase inherits it.
**Files:** `app/globals.css`, `tailwind.config.js`, `app/layout.tsx` (body bg / toast theme)
**Tasks:**
- [ ] Rewrite `:root` tokens per §4 (light bg, indigo accent, new severity colors, radii)
- [ ] Update `body` background to `#f1f5f9`, text to `#0f172a`
- [ ] Re-skin `.glass-card` → solid white card (`#fff`, `1px #e5e7eb`, `0 1px 3px rgba(15,23,42,.04)`)
- [ ] Re-skin `.input-base`, `.btn-primary` (indigo, no gradient), `.btn-ghost`, `.btn-danger`
- [ ] Re-skin `.badge-*` severity classes to new color set
- [ ] Replace `float/glow/shimmer` keyframes with `fadeUp`, `spin`, `barpulse`
- [ ] Update scrollbar colors; restyle `react-hot-toast` to light theme
- [ ] Sync Tailwind `theme.extend.colors` with the new tokens
**Acceptance:** Existing app still renders (unstyled-correct) on a light background with indigo buttons; no dark surfaces remain from tokens.

---

### Phase 1 — App shell (sidebar + breadcrumb + view routing) ✅
**Goal:** Replace the top-header/centered-column shell with the sidebar layout and in-app view switching.
**Files:** new `components/layout/Sidebar.tsx`, `components/layout/Topbar.tsx`, `components/layout/AppShell.tsx`; refactor `app/page.tsx`; retire/repurpose `components/ui/Header.tsx`
**Tasks:**
- [ ] Build `Sidebar` (264px): logo lockup, **New Scan** button, Workspace/Dashboard nav items (active state `#eef2ff`/`#4f46e5`), **Recent Sessions** list, Settings + user block at bottom
- [ ] Build `Topbar` (56px): breadcrumb (`root / leaf`) + bell + help icons
- [ ] Add `view` state (`workspace | dashboard | settings`) + nav handlers
- [ ] Wire **Recent Sessions** to existing scan history API; clicking opens that session's results
- [ ] Wire **New Scan** → reset to input phase
- [ ] Compose `AppShell` (sidebar + topbar + main slot); render only when authenticated
- [ ] Make sidebar sticky/full-height; main area scrolls independently
**Acceptance:** Authenticated users see the sidebar + breadcrumb; switching Workspace/Dashboard/Settings swaps the main panel; Recent Sessions populated from real data.

---

### Phase 2 — Workspace: input phase (form) ✅
**Goal:** Rebuild the analysis form to match the design, with the centered→sticky-left phase behavior.
**Files:** `components/analysis/ModeSelector.tsx`, `QuickAnalysis.tsx`, `ExpertAnalysis.tsx`; workspace container in `page.tsx`
**Tasks:**
- [ ] Centered hero (icon tile + "Analyze your AI agent" + subtitle) shown only in `input` phase
- [ ] Convert mode selector to **segmented Quick/Expert tab** (indigo active) inside the card
- [ ] Agent Description textarea (label uppercase, `#fafbfc` bg, focus `#a5b4fc`)
- [ ] **Preset pills** (Recruiter Bot / Code Assistant / Customer Support) that fill the description
- [ ] **Integration toggle rows** (MCP / RAG) with switch knobs + active row highlight
- [ ] Primary **Analyze Agent** button (indigo, shield icon, loading label swap)
- [ ] Keep Expert mode's richer config fields; restyle to the new system
- [ ] Form wrapper: `max-w-560` centered in input phase → `360px` sticky-left in results phase
**Acceptance:** Form matches design pixel-intent; presets/toggles work; submitting triggers the existing analyze handlers unchanged.

---

### Phase 3 — Workspace: analyzing phase ✅
**Goal:** Replace the loading overlay with the design's spinner + framework checklist.
**Files:** new `components/analysis/AnalyzingPanel.tsx`; `page.tsx`
**Tasks:**
- [ ] Card with centered spinner (`border-top:#4f46e5`, `spin .8s`)
- [ ] "Running security analysis…" + sub-line
- [ ] Step checklist: MAESTRO ✓, ATFAA ✓, MCP/RAG in-progress (`barpulse`), score pending — shown conditionally on mcp/rag flags
- [ ] Reuse for both standard analyze and adaptive-loop in-progress states
**Acceptance:** During analysis the new panel shows in the results column; checklist reflects selected integrations.

---

### Phase 4 — Workspace: results phase (gauge + breakdown + vuln cards) ✅
**Goal:** Rebuild results to the new visual language while keeping all data the current `ResultsDisplay` shows.
**Files:** `components/ResultsDisplay.tsx`, `PayloadsDisplay.tsx`, `EvaluationDisplay.tsx`; new `components/results/RiskGauge.tsx`, `SeverityBreakdown.tsx`, `VulnCard.tsx`
**Tasks:**
- [ ] Results header: green check + title + Download PDF + New Scan buttons
- [ ] **RiskGauge**: conic-gradient ring (band color × score), center score + "Risk Score", band label
- [ ] **SeverityBreakdown**: CRITICAL/HIGH/MEDIUM/LOW rows with proportional bars + counts
- [ ] **VulnCard** (expandable): severity badge + title + MAESTRO pill + ATFAA pill + chevron → description, **payload** dark block (`#0f172a`, JetBrains Mono), **mitigation** green block
- [ ] Preserve PDF export (`jspdf`) — restyle trigger only
- [ ] Re-skin **adaptive-loop** UI (discovery chips, rounds table, PAIR badge) to light theme; keep all fields
- [ ] Re-skin payload/evaluation sub-displays to light theme
**Acceptance:** Real analysis results render in the new layout; expand/collapse works; gauge/bars reflect actual counts; adaptive-loop output intact and readable on light theme.

---

### Phase 5 — Dashboard view ✅
**Goal:** Build the Dashboard accessible from the sidebar.
**Files:** new `components/dashboard/Dashboard.tsx`; data from scan-history API
**Tasks:**
- [ ] Title + subtitle
- [ ] 4 stat cards: Total Scans, Open Critical (red card), Avg Risk Score, Agents Tested — computed from real history
- [ ] Trend/history placeholder panel (chart later; static panel for now)
**Acceptance:** Dashboard shows real aggregate numbers from the user's scans.

---

### Phase 6 — Settings view ✅
**Goal:** Build the Settings view from the design.
**Files:** new `components/settings/Settings.tsx`; persist prefs (localStorage or profile API)
**Tasks:**
- [ ] Analysis Defaults card: "Default to Expert mode", "Enable MCP by default" toggles
- [ ] Notifications card: "Email me on critical findings" toggle (show user email)
- [ ] Wire toggles to a persisted preferences store; apply "default mode/MCP" to new scans
**Acceptance:** Toggles persist across reloads and affect new-scan defaults.

---

### Phase 7 — Polish, responsive & QA ⬜
**Goal:** Finish animations, responsiveness, accessibility, and a full regression pass.
**Files:** across components; `globals.css`
**Tasks:**
- [ ] `fadeUp` entrance on view/phase transitions (Framer Motion or CSS)
- [ ] Responsive: sidebar collapses to icon/drawer < 1024px; results grid stacks on mobile
- [ ] Focus states, aria-labels, keyboard nav, 44px touch targets
- [ ] Re-skin any remaining dark remnants; verify `react-hot-toast` light theme
- [ ] Manual QA: auth → quick scan → results → PDF → adaptive loop → dashboard → settings
- [ ] `next build` / lint clean
**Acceptance:** Smooth, responsive, accessible; full happy-path verified; build passes.

---

### Phase 8 — Auth / landing / profile restyle ⏸️ (deferred per D2)
**Goal:** Bring `AuthModal`, landing/hero, and `/profile` into the new light/indigo system.
**Files:** `components/auth/AuthModal.tsx`, `app/page.tsx` (hero), `app/profile/page.tsx`
**Tasks:**
- [ ] Restyle auth modal to light theme
- [ ] Restyle/relocate landing/hero (or fold into shell)
- [ ] Fold profile into Settings + sidebar user menu, or restyle `/profile`
**Acceptance:** No dark-theme screens remain anywhere in the app.

---

## 6. Risks & Notes
- **Functionality preservation is the hard constraint.** The current app is richer than the mockup (adaptive loop, PAIR, discovery, evaluation tables). Every re-skin must keep those data paths working — re-skin markup, don't delete logic.
- `support.js` in the bundle is the Claude Design runtime — **ignore** it; not used in implementation.
- Sidebar **Recent Sessions** and **Dashboard** both consume scan-history data; confirm the API shape early (Phase 1) so Phases 1/5 align.
- Keep `lib/api.ts` and `types/index.ts` as stable contracts; UI changes should not require backend changes.

---

## 7. Progress Log
_Newest first. Update one entry per phase completion (date + what shipped + any deviations)._

- **2026-06-23** — Plan created. Decisions locked (D1–D4). All phases ⬜ Not started. Awaiting go-ahead to begin Phase 0.
- **2026-06-23** — Phases 0–6 executed in one session. Summary of changes:
  - **Phase 0:** `globals.css` fully rewritten (light/indigo tokens, new component classes, animations). `tailwind.config.js` synced. `layout.tsx` toast restyled to light theme.
  - **Phase 1:** New `components/layout/Sidebar.tsx`, `Topbar.tsx`, `AppShell.tsx`. `page.tsx` refactored to mount AppShell for authenticated users; in-app Workspace/Dashboard/Settings routing wired.
  - **Phase 2:** `ModeSelector.tsx` replaced with segmented Quick/Expert tab. Form wrapper behavior (centered input phase → sticky 360px left panel in results) wired in `page.tsx`. AnalyzingPanel added.
  - **Phase 3:** `components/analysis/AnalyzingPanel.tsx` created (spinner + MCP/RAG-aware checklist).
  - **Phase 4:** `ResultsDisplay.tsx` and `EvaluationDisplay.tsx` dark-theme colors (hard-coded hex, glass-card, text-white) replaced with light-theme CSS vars. Adaptive-loop output section reskinned inside `page.tsx`.
  - **Phase 5:** `components/dashboard/Dashboard.tsx` built (4 stat cards + recent scans table from real scan history API).
  - **Phase 6:** `components/settings/Settings.tsx` built (Analysis Defaults + Notifications toggles, localStorage persistence).
  - TypeScript: `npx tsc --noEmit` → 0 errors after all phases.
  - **Remaining:** Phase 7 (Polish/responsive/QA) and Phase 8 (Auth/landing/profile restyle, deferred) still ⬜.
