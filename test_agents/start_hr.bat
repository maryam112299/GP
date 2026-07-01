@echo off
REM Launches the PeopleOps-HR-Copilot victim agent on port 9200.
REM Self-contained: uses the VICTIM Groq key (same as the bank mini-app). The
REM PAIR refiner uses its own separate key (REFINER_GROQ_API_KEY in backend\.env).

set GROQ_API_KEY=gsk_
set HR_AGENT_PORT=9200

cd /d "%~dp0"
call venv\Scripts\activate.bat
python hr_agent.py
