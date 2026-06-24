@echo off
REM Launch NovaBank-Concierge (real mini-app) on port 9100.
REM Self-contained: no need to set GROQ_API_KEY in the shell first.

set GROQ_API_KEY=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
set BANK_AGENT_PORT=9100

cd /d "%~dp0"
echo Starting NovaBank-Concierge on http://localhost:9100 ...
call venv\Scripts\activate.bat
python bank_agent.py
pause
