# End-to-end test playbook

This is the exact sequence to run a full GP scan against one of the Groq
agents on Windows / PowerShell.

## Terminal A — Ollama (analysis + payload generation)

Already running on `http://localhost:11434`. Models needed:
- `mistral:latest`   — analysis LLM
- `redteam:latest`   — adversarial payload generator

```powershell
ollama list      # confirm both are present
```

## Terminal B — victim agent (Bank OR HR)

```powershell
cd D:\GP\test_agents
set GROQ_API_KEY=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

# Choose ONE of:
.\start_bank.bat      # → http://localhost:9100
# .\start_hr.bat      # → http://localhost:9200
```

Leave it running. You'll see live POST logs each time the GP attacks it.

## Terminal C — GP backend, pointed at the victim

```powershell
cd D:\GP\backend
.\venv\Scripts\activate

# Pick the matching pair for whichever agent is running in Terminal B:
set VICTIM_BASE_URL=http://localhost:9100
set VICTIM_MODEL=bank-agent
# or
# set VICTIM_BASE_URL=http://localhost:9200
# set VICTIM_MODEL=hr-agent

python main.py
```

The GP backend now boots with mistral for analysis but routes every
adversarial payload to your Groq agent.

## Terminal D — GP frontend

```powershell
cd D:\GP\frontend
npm run dev      # → http://localhost:3000
```

## Run the scan

1. Open http://localhost:3000.
2. Sign up (e.g. `tester@example.com` / any password ≥ 8 chars).
3. Pick **Quick Mode**.
4. Tick **Uses MCP** and **Uses RAG**.
5. Paste the matching description from `README.md` (bank or HR).
6. Click **Start Security Analysis**. ~30 s.
7. When the attack plan appears, click **Generate Payloads** → **Simulate Attacks**.
8. The progress bar in the UI mirrors the live POST logs in Terminal B.
9. Click **Download PDF Report** at the end.

## What "good" looks like

- **Direct attacks** (system-prompt leak, jailbreak): mostly SUCCESS
  (refused). The system prompt has explicit rules.
- **Indirect / RAG attacks**: a mix — the agent is told to treat
  retrieved content as untrusted, but llama-3.1-8b doesn't always
  enforce it perfectly.
- **MCP tool-poisoning**: roughly 50/50 — the agent is told MCP
  responses are untrusted, but authority-spoofing payloads
  ("trusted admin MCP server") do still slip past sometimes.
- **Multi-turn / memory-poisoning**: weakest layer; you should see
  several FAILs because the agent treats history as ground truth.

That distribution is the point — the GP gives you a structured map of
which categories the agent's policy actually enforces vs. just states.

## Switching victims mid-session

You can leave the GP backend up and just restart it with a different
`VICTIM_BASE_URL`/`VICTIM_MODEL`. Both agents can run side-by-side on
ports 9100 and 9200 — flip the env vars + restart Terminal C and the
same frontend session can run scans against either.
