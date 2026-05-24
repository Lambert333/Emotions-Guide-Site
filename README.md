# Emotions Guide Web

Full-stack web application for tracking emotional state, tests, charts, Firebase authentication, and AI-assisted recommendations.

## Stack

- Frontend: React 18, TypeScript, Vite, Firebase client SDK.
- Backend: FastAPI, Firebase Admin SDK, Realtime Database, PyJWT, SlowAPI, HTTPX.

## Repository Safety

Real secrets must not be committed. Keep local values in ignored files:

- `backend/.env`
- `Frontend/.env`
- `Frontend/.env.local`
- `backend/serviceAccountKey.json`
- `backend/certs.json`

Use the tracked templates instead:

- `backend/.env.example`
- `Frontend/.env.example`

For local backend development, keep the Firebase service account JSON outside the repository and point to it with `FIREBASE_SERVICE_ACCOUNT_PATH`. If a service account key was ever exposed publicly, rotate it in Google Cloud/Firebase and delete the old key.

For CI/CD, store runtime secrets in GitHub Actions Secrets only when a workflow needs them. For Google/Firebase deployments, prefer GitHub OIDC with Google Workload Identity Federation over long-lived service account JSON secrets. In production, use the hosting provider's environment variables or a secret manager.

`VITE_*` values and Firebase web config are bundled into frontend code, so they are not a place for private secrets. Protect Firebase access with Auth, database rules, API key restrictions, and allowed domains.

## Frontend Setup

```bash
cd Frontend
cp .env.example .env.local
npm ci
npm run dev
```

For a production build:

```bash
cd Frontend
npm run build
```

## Backend Setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
```

Fill `backend/.env` with local values, then run:

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

## GitHub Push Checklist

Before the first commit or push, verify ignored files:

```bash
git check-ignore -v backend/.env backend/serviceAccountKey.json Frontend/node_modules Frontend/dist
git status --short
git diff --cached --name-only
```

Make sure `.env`, `.env.local`, service account JSON files, `node_modules`, `dist`, and `__pycache__` are not staged.
