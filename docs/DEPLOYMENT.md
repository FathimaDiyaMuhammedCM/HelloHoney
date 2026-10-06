# 🌐 HelloHoney Cloud Deployment Guide

This guide explains how to make **HelloHoney (HoneyWatch SOC)** publicly accessible via cloud hosting platforms.

---

## ⚡ Summary of Changes Made for Cloud Readiness

1. **Unified Full-Stack Serving**:
   - The Node.js backend now serves the compiled React frontend static files from `frontend/dist/` in production.
   - REST API, WebSockets (`socket.io`), and Frontend SPA run together seamlessly on a single port (`PORT=5000` or cloud-assigned `$PORT`).
2. **Dynamic Client Configuration**:
   - `frontend/src/services/api.js` automatically uses relative `/api` or respects `VITE_API_URL`.
   - `frontend/src/hooks/useRealtime.js` dynamically connects to the current host origin (`window.location.origin`) or `VITE_SOCKET_URL`.
3. **Production Scripts in Root `package.json`**:
   - `npm run build`: Installs frontend and backend dependencies and compiles the Vite production bundle.
   - `npm start`: Starts the backend server.
4. **Deployment Manifests Included**:
   - [`render.yaml`](../render.yaml): Blueprint for 1-click deployment on Render.
   - [`railway.json`](../railway.json): Configuration for Railway.
   - [`Dockerfile`](../Dockerfile): Multi-stage container build for any Docker-based cloud (Fly.io, AWS ECS, GCP Cloud Run, DigitalOcean).
   - [`frontend/vercel.json`](../frontend/vercel.json): Routing rewrite rule if hosting frontend on Vercel.

---

## Option 1: Deploy on Render (Recommended, Free Tier)

Render provides free hosting for Web Services with automatic HTTPS.

### Step 1: Push your project to GitHub
In your project terminal:
```bash
git add .
git commit -m "Prepare HelloHoney for cloud deployment"
# Create a repository on GitHub (e.g. hellohoney), then link and push:
git remote add origin https://github.com/<YOUR_GITHUB_USERNAME>/<YOUR_REPO_NAME>.git
git push -u origin main
```

### Step 2: Deploy on Render
1. Go to [Render.com](https://render.com) and log in.
2. Click **New +** -> **Web Service**.
3. Select your GitHub repository.
4. Configure the service settings:
   - **Name**: `hellohoney` (or your preferred name)
   - **Environment**: `Node`
   - **Region**: Closest to you (e.g., Oregon, Frankfurt, Singapore)
   - **Branch**: `main`
   - **Build Command**: `npm run build`
   - **Start Command**: `npm start`
   - **Instance Type**: `Free`
5. Under **Environment Variables**, add:
   - `NODE_ENV`: `production`
   - `PORT`: `5000`
   - `JWT_SECRET`: (Click *Generate* or enter a random secure string)
   - `JWT_EXPIRES_IN`: `8h`
   - `FRONTEND_URL`: `*`
   - `SIMULATION_MODE`: `true`
   *(Optional)* If using MongoDB Atlas, add `MONGO_URI`. If not specified, the backend automatically uses its built-in in-memory database fallback.
6. Click **Deploy Web Service**.
7. Once deployed, Render will provide a public URL like:
   `https://hellohoney-xxxx.onrender.com`

---

## Option 2: Deploy on Railway (Free Trial / Pay-as-you-go)

Railway detects the repository setup and provisions the application automatically.

1. Go to [Railway.app](https://railway.app) and sign in with GitHub.
2. Click **New Project** -> **Deploy from GitHub repo**.
3. Select your `hellohoney` repository.
4. Railway will automatically detect the root [`railway.json`](../railway.json) or [`Dockerfile`](../Dockerfile).
5. In **Variables**, add:
   - `NODE_ENV`: `production`
   - `JWT_SECRET`: A secure random string
   - `SIMULATION_MODE`: `true`
6. Go to **Settings** -> **Networking** -> **Generate Domain** to get your public `https://....up.railway.app` URL.

---

## Option 3: Separate Deploy (Frontend on Vercel + Backend on Render/Railway)

If you prefer hosting the React frontend on Vercel:

1. Deploy the Backend to Render or Railway as an API service.
   - Note the backend URL: e.g. `https://hellohoney-api.onrender.com`.
2. Deploy the Frontend on [Vercel](https://vercel.com):
   - Import the repository in Vercel.
   - Set **Root Directory** to `frontend`.
   - In Environment Variables, set:
     - `VITE_API_URL`: `https://hellohoney-api.onrender.com/api`
     - `VITE_SOCKET_URL`: `https://hellohoney-api.onrender.com`
   - Deploy.

---

## 🗄️ Database: MongoDB Atlas (Optional, For Persistent Data)

By default, the backend includes an in-memory MongoDB fallback for instant demos. For permanent database persistence across service restarts:

1. Create a free account at [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
2. Create a free shared cluster (**M0 Free Tier**).
3. Under **Database Access**, create a database user (e.g. `hh_admin` + strong password).
4. Under **Network Access**, click **Add IP Address** -> select **Allow Access from Anywhere** (`0.0.0.0/0`).
5. Click **Connect** -> **Drivers** (Node.js) -> copy the connection string:
   `mongodb+srv://hh_admin:<password>@cluster0.xxxx.mongodb.net/hellohoney?retryWrites=true&w=majority`
6. Add this string as `MONGO_URI` in your Render / Railway environment variables.

---

## 🔑 Default Credentials for Login

Once your public URL is live, log in using any of the default pre-seeded accounts:

| Role | Email | Password |
|---|---|---|
| **Admin** | `admin@hellohoney.local` | `Admin123!` |
| **Analyst** | `analyst@hellohoney.local` | `Analyst123!` |
| **Viewer** | `viewer@hellohoney.local` | `Viewer123!` |

> **Tip:** You can immediately test the platform using the **Simulation** buttons on the dashboard (Failed SSH Login, SSH Brute Force, Port Scan, Web Probe, Multi-Stage Attack) to generate live alerts and incident tickets.
