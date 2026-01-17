# Email Header Analyzer

An interactive web app to analyze raw email headers: extract key fields, trace IP hops, geolocate public IPs, visualize the route on a map, and build a timeline. Includes login, a dashboard of past analyses, and CSV export.

## Features
- Upload `.eml` or paste header text
- Extracted data table (From/To/Subject/Date/Message-ID)
- IP trace with private/public detection and geolocation
- Route map with markers and polyline (Leaflet + OpenStreetMap)
- Timeline of `Received` hops
- Login/Register with JWT
- Dashboard with filters and CSV export

## Quick Start (Windows)
- Prerequisites: Python 3.10+
- In `c:\Users\Karan\OneDrive\Desktop\New folder`:
  - Create venv: `python -m venv venv`
  - Activate (PowerShell): `./venv/Scripts/Activate.ps1`
  - Install deps: `pip install -r requirements.txt`
  - Configure env: copy `.env.example` to `.env` and set variables
  - Run: `python app.py`
  - Open: `http://127.0.0.1:5000/`

## Environment Variables
- `MONGO_URI`: optional; if set, analyses and users are stored in MongoDB; if not, JSON files are saved under `data/`
- `JWT_SECRET`: recommended; secret used to sign JWTs for auth
- `IPINFO_TOKEN`: optional; improves IP geolocation accuracy via ipinfo.io

Example:
```
JWT_SECRET=change-me
MONGO_URI=mongodb+srv://<user>:<pass>@<cluster-url>/email_header_analyzer
IPINFO_TOKEN=your-ipinfo-token
```

## Using The App
- Home page (`/`): paste header or upload `.eml`, click `Analyze`
- Results show Extracted Data, Route Map and Timeline
- Register (`/register`) then Login (`/login`) to access Dashboard (`/dashboard`)
- Dashboard supports filtering by sender, IP and date; click `Export CSV` for a download

## API Overview
- Page routes: defined in `app.py:259-277`
- APIs: defined in `app.py:279-426`

- `POST /api/register`
  - Body: `{"email":"...","password":"..."}`
  - Response: `{"token":"<jwt>"}`

- `POST /api/login`
  - Body: `{"email":"...","password":"..."}`
  - Response: `{"token":"<jwt>"}`

- `POST /api/analyze`
  - Form-data: `header_text` or `eml_file` (`.eml` only)
  - Response: analysis JSON (fields, `ip_trace`, `geolocation`, `hops`, `spoof_check`)

- `GET /api/history`
  - Auth: `Authorization: Bearer <jwt>`
  - Query: `sender`, `ip`, `since`, `until` (ISO dates)
  - Response: list of analyses

- `GET /api/export`
  - Auth: `Authorization: Bearer <jwt>`
  - Response: CSV file

## Project Structure
- `app.py`: Flask app, routes, parsing, geolocation, storage
- `templates/base.html`: layout, includes Bootstrap, Leaflet, `static/css/styles.css`
- `templates/index.html`: upload/paste UI, results, map, timeline
- `templates/dashboard.html`: filters and history table
- `templates/login.html`, `templates/register.html`: auth pages
- `static/js/main.js`: frontend logic (analyze, auth, history, export)
- `static/css/styles.css`: dark theme, enhanced cards/buttons/timeline
- `data/`: local JSON storage fallback
- `logs/app.log`: runtime logs

## Troubleshooting
- PowerShell script execution: if activation is blocked, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
- Port conflicts: change `app.run(..., port=5000)` in `app.py:429-430`
- Static assets: the app serves `/static/...` automatically; ensure you use `http://127.0.0.1:5000/`

## Notes
- Geolocation uses ipinfo.io; private IPs are marked and not geolocated
- When `MONGO_URI` is unset, user and analysis data are stored under `data/` as JSON
