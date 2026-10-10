# VULN-X — Intelligent Vulnerability Scanner

React/Vite frontend and FastAPI backend for a non-destructive, authorized defensive assessment. Includes account login, scan history, TCP port checks, HTTP security-header checks, PDF reports, SerpApi threat-intelligence context, demo scan, and CSV export of results.

## Requirements
- Python 3.10+
- Node.js 18+ and npm

## Backend (PowerShell)
```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env: set a unique JWT_SECRET. SERPAPI_KEY is optional.
python -m uvicorn app.main:app --reload --port 8000
```
Open http://127.0.0.1:8000/docs to verify the API is running.

## Frontend (second PowerShell terminal)
```powershell
cd frontend
npm install
npm run dev
```
Open http://127.0.0.1:5173. Keep both terminals running.

## First test
1. Create an account in the UI.
2. Select **RUN DEMO SCAN** to verify the complete workflow without connecting to a target.
3. For a real scan, enter a hostname or URL for a system you own or have explicit permission to assess. The explicit URL port is included in the port checks.
4. Download the PDF report or select **EXPORT CSV** to export summary, port states, findings, evidence, and recommendations.

## Scanner limitations
This project performs a limited set of TCP connection checks and HTTP response-header checks. It is not a full vulnerability scanner and does not prove that a target is secure. An HTTP assessment failure is marked **incomplete** instead of being reported as a clean scan. Closed ports and missing responses can also be caused by firewalls, routing, or service configuration.

## Security notes
- Scan only systems you own or have explicit permission to assess.
- Copy `.env.example` to `.env`; never commit `.env`, credentials, API keys, JWT secrets, or local database files.
- Rotate any API key that was included in a shared archive.
- SerpApi is optional. Without a configured key, threat-intelligence results may be empty; the scanner should still complete its core checks.
