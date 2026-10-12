# 🌐 HelloHoney Deployment Guide

HelloHoney is a **lab / demo** SOC platform. The recommended production topology is a **split deploy**:

| Component | Host | Source | Notes |
|---|---|---|---|
| Backend API + WebSockets (Socket.IO) | **Render** (Node web service) | `backend/` | config: [`render.yaml`](../render.yaml) |
| Frontend SPA | **Vercel** (static Vite build) | `frontend/` | config: [`frontend/vercel.json`](../frontend/vercel.json) |
| Honeypot | **NOT deployed** | `honeypot/` | lab-only — never expose to the public internet |

The frontend is a static bundle that calls the backend directly using `VITE_API_URL` (REST) and
`VITE_SOCKET_URL` (Socket.IO). Both hosts deploy from the **same GitHub repository**.

> ⚠️ **Security notes**
> - This is a demo with simulated data. Use a strong `JWT_SECRET`, set real passwords, and set
>   `FRONTEND_URL` to your Vercel origin (avoid `*` in anything long-lived).
> - The honeypot binds to localhost and must remain local.
> - Do not commit secrets — API passwords and `MONGO_URI` are set as platform env vars.

---

## Prerequisites

- A **GitHub** account (Render and Vercel both deploy from GitHub).
- This project pushed to a GitHub repository.
- *(Optional, recommended)* A free **MongoDB Atlas** cluster for persistent data (see
  [Database](#database-in-memory-vs-mongodb-atlas)).

---

## Step 1 — Push the project to GitHub

From the project root:

```bash
git add .
git commit -m "HelloHoney: security hardening + dashboard + cloud deploy config"

# Create an empty repo on GitHub (e.g. hellohoney), then:
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/hellohoney.git
git branch -M main
git push -u origin main
```

---

## Step 2 — Deploy the backend on Render

### Option A — Blueprint (uses `render.yaml`) ✅ recommended

1. Go to [render.com](https://render.com) → **New +** → **Blueprint**.
2. Select your `hellohoney` repository. Render reads [`render.yaml`](../render.yaml) and creates
   the `hellohoney-api` web service.
3. When prompted, fill the secret variables (`sync: false`):
   - `FRONTEND_URL` — your Vercel URL (you can put a placeholder now and update in Step 4)
   - `SEED_ADMIN_PASSWORD`, `SEED_ANALYST_PASSWORD`, `SEED_VIEWER_PASSWORD`
4. `JWT_SECRET` is auto-generated; `SEED_DEFAULT_USERS=true` and `SEED_DEMO_DATA=true` are preset.
5. Click **Apply** / **Deploy**. Wait for “Live”.
6. Note the URL, e.g. `https://hellohoney-api.onrender.com`.
7. Verify: open `https://hellohoney-api.onrender.com/api/health` → `{"status":"ok", ...}`.

### Option B — Manual Web Service

| Setting | Value |
|---|---|
| Root Directory | *(repo root)* |
| Environment | Node |
| Build Command | `npm --prefix backend install` |
| Start Command | `node backend/server.js` |
| Health Check Path | `/api/health` |

Environment variables (all required unless noted):

| Variable | Value |
|---|---|
| `NODE_ENV` | `production` |
| `JWT_SECRET` | strong random string (32+ chars) |
| `JWT_EXPIRES_IN` | `8h` |
| `FRONTEND_URL` | your Vercel origin (Step 4) |
| `SIMULATION_MODE` | `true` |
| `SEED_DEFAULT_USERS` | `true` |
| `SEED_DEMO_DATA` | `true` |
| `SEED_ADMIN_PASSWORD` | *choose a strong password* |
| `SEED_ANALYST_PASSWORD` | *choose a strong password* |
| `SEED_VIEWER_PASSWORD` | *choose a strong password* |
| `MONGO_URI` | *(optional)* Atlas connection string |

> **PORT:** do **not** set it — Render injects its own `PORT` and the backend reads `process.env.PORT`.

---

## Step 3 — Deploy the frontend on Vercel

1. Go to [vercel.com](https://vercel.com) → **Add New… → Project** → import the same repository.
2. **Root Directory:** `frontend`
3. Framework preset: **Vite** (auto-detected). Build `npm run build`, output `dist`.
4. **Environment Variables** (Production):
   - `VITE_API_URL` = `https://hellohoney-api.onrender.com/api`
   - `VITE_SOCKET_URL` = `https://hellohoney-api.onrender.com`
5. **Deploy.** Note the URL, e.g. `https://hellohoney.vercel.app`.

> Vite inlines `VITE_*` variables **at build time**. If you change them, trigger a new deployment.

---

## Step 4 — Wire CORS (connect the two)

Back on **Render** → `hellohoney-api` → **Environment**:

```
FRONTEND_URL = https://hellohoney.vercel.app
```

Save (this redeploys). This allows the REST API **and** the Socket.IO handshake from the frontend.
Multiple origins can be comma-separated; `*` reflects any origin (fine for a throwaway demo only).

---

## Step 5 — Log in

Open your Vercel URL and log in with the seeded demo accounts:

| Role | Email | Password |
|---|---|---|
| Admin | `admin@hellohoney.local` | your `SEED_ADMIN_PASSWORD` |
| Analyst | `analyst@hellohoney.local` | your `SEED_ANALYST_PASSWORD` |
| Viewer | `viewer@hellohoney.local` | your `SEED_VIEWER_PASSWORD` |

The dashboard opens pre-populated with demo events/alerts/incidents.

---

## Verification checklist

- [ ] `GET https://<backend>/api/health` → `200 {"status":"ok"}`
- [ ] Frontend URL loads the login page (Vercel).
- [ ] Login succeeds with the admin account.
- [ ] Dashboard cards are non-zero (Total Events, Active Alerts, …).
- [ ] Socket.IO connects (browser console: no CORS/auth errors; live feed updates when you
      click a **Simulation** button).
- [ ] `FRONTEND_URL` on Render equals the exact Vercel origin (scheme + host, no trailing slash).

---

## Database: in-memory vs MongoDB Atlas

- **Default (no `MONGO_URI`):** the backend starts an in-memory MongoDB. Data is **lost on every
  restart/redeploy**, then `SEED_DEMO_DATA=true` re-seeds sample data. Perfect for a demo.
- **Persistent (recommended):** create a free **M0** cluster at
  [MongoDB Atlas](https://www.mongodb.com/cloud/atlas):
  1. Database Access → create a user.
  2. Network Access → allow `0.0.0.0/0` (or Render egress IPs).
  3. Connect → Drivers → copy the string and set it as `MONGO_URI` on Render:
     `mongodb+srv://<user>:<pass>@cluster0.xxxx.mongodb.net/hellohoney?retryWrites=true&w=majority`
  With Atlas, seeding runs only when the database is **empty**, so real data is never overwritten.

---

## Alternative — single full-stack service (Docker / one host)

A [`Dockerfile`](../Dockerfile) is included that builds the frontend and serves it together with the
API from one Node process (one port). Use it on any Docker host (Fly.io, Cloud Run, Railway, …).
On that model, one service serves everything and `FRONTEND_URL` can be its own URL.

---

## Environment variable reference

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | HTTP port (Render sets this automatically) |
| `NODE_ENV` | — | `production` disables verbose errors |
| `MONGO_URI` | *(empty)* | Mongo connection string; falls back to in-memory if unset |
| `JWT_SECRET` | *(required)* | 32+ char signing secret; server refuses to start without it |
| `JWT_EXPIRES_IN` | `2h` | Access-token lifetime |
| `FRONTEND_URL` | `http://localhost:5173` | CORS allowlist (comma-separated) for REST + Socket.IO |
| `SIMULATION_MODE` | `false` | Enables the lab **Simulation** buttons |
| `SEED_DEFAULT_USERS` | `false` | Seed admin/analyst/viewer on first start |
| `SEED_ADMIN_PASSWORD` / `SEED_ANALYST_PASSWORD` / `SEED_VIEWER_PASSWORD` | — | Passwords for the seeded accounts |
| `SEED_DEMO_DATA` | `false` | Seed sample events/alerts/incidents when the DB is empty |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| CORS error / Socket.IO won’t connect | `FRONTEND_URL` doesn’t match the Vercel origin exactly. Update it on Render and redeploy. |
| Login says “No users exist” | `SEED_DEFAULT_USERS=true` plus all three `SEED_*_PASSWORD` must be set before first start. |
| Dashboard is empty | `SEED_DEMO_DATA=true` (and the DB empty), or use a **Simulation** button. |
| 401 on every call after a while | Token expired (`JWT_EXPIRES_IN`) or `JWT_SECRET` changed — log in again. |
| API calls 404 from Vercel | `VITE_API_URL` missing/wrong; set it and **redeploy** (Vite reads it at build time). |
| “Invalid or expired token” on realtime only | `VITE_SOCKET_URL` missing; the socket must point at the backend, not Vercel. |
