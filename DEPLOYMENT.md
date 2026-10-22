# PhishGuard Cloud — Master Cloud Deployment Guide

PhishGuard Cloud is an enterprise-grade AI phishing detection and threat intelligence platform designed to be deployed across **any major cloud environment**:

1. **Option 1 (Recommended — Free & Easiest):** Render (FastAPI Backend) + Vercel / Netlify (React Frontend)
2. **Option 2 (Self-Hosted VPS / Container Cloud):** Docker & Docker Compose (PostgreSQL + FastAPI + Nginx)
3. **Option 3 (Enterprise Serverless):** AWS Serverless (API Gateway HTTP API + Lambda + S3 Private Origin + CloudFront CDN)
4. **Option 4 (Container PaaS):** Railway.app or Fly.io

---

## Architecture Matrix

| Platform | Compute Layer | Database Layer | Frontend CDN | Setup Time | Cost Tier |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Render + Vercel** | Render Web Service (Python 3.12) | SQLite / Render PostgreSQL | Vercel Global Edge Network | ~5 mins | **Free Tier Available** |
| **Docker Compose** | Docker Container (Gunicorn/Uvicorn) | PostgreSQL 16 Alpine container | Nginx Alpine Container | ~3 mins | VPS Cost (~$4–$6/mo) |
| **AWS Serverless** | AWS Lambda (Mangum + Python 3.12) | Serverless SQLite or RDS Postgres | AWS CloudFront + S3 (OAC) | ~10 mins | Pay-per-request / Free Tier |
| **Railway** | Railway Service (Procfile) | Railway Postgres Plugin | Railway Static / Vercel | ~5 mins | Free Trial / Usage-based |

---

## Option 1: Deploy on Render + Vercel (Recommended)

This is the fastest, completely free zero-setup deployment method with automated continuous deployment on `git push`.

### Step 1.1: Push Your Code to GitHub
Ensure your repository is pushed to your GitHub account:
```bash
git add .
git commit -m "feat: complete cloud deployment configuration and new security tools"
git push origin main
```

### Step 1.2: Deploy Backend on Render.com
1. Go to [Render Dashboard](https://dashboard.render.com/) and click **New +** → **Web Service**.
2. Connect your GitHub repository (`flexiProject`).
3. Set the following settings:
   - **Name:** `phishguard-api`
   - **Root Directory:** `backend`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan:** Free
4. In **Environment Variables**, add:
   - `PYTHON_VERSION`: `3.12.5`
   - `SECRET_KEY`: *(Generate a secure 32+ character random string)*
   - `CORS_ORIGINS`: `*`
   - `DATABASE_URL`: `sqlite:///./phishing.db`
   - `VIRUSTOTAL_API_KEY`: *(Optional: Your VirusTotal v3 API key)*
5. Click **Deploy Web Service**.
6. Once deployed, copy your backend URL (e.g. `https://phishguard-api.onrender.com`).
   - Verify health: `https://phishguard-api.onrender.com/health`
   - View API docs: `https://phishguard-api.onrender.com/docs`

> [!TIP]
> You can also use Render's **Blueprints**: simply click **New +** → **Blueprint**, select your repo, and Render will automatically detect [`render.yaml`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/render.yaml) to deploy both backend and frontend simultaneously.

### Step 1.3: Deploy Frontend on Vercel
1. Go to [Vercel Dashboard](https://vercel.com/) and click **Add New...** → **Project**.
2. Import your GitHub repository (`flexiProject`).
3. In **Project Settings**:
   - **Root Directory:** Click `Edit` and select `frontend`.
   - **Framework Preset:** Vite (auto-detected).
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
4. In **Environment Variables**, add:
   - `VITE_API_URL`: `https://phishguard-api.onrender.com` *(Replace with your Render API URL from Step 1.2)*
5. Click **Deploy**.
6. Your web application is now live at `https://your-project.vercel.app`!
   - Full SPA deep-linking and page refresh are handled by [`vercel.json`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/frontend/vercel.json).

---

## Option 2: Deploy with Docker & Docker Compose (Self-Hosted VPS / Cloud Server)

Ideal for single-server production deployment on AWS EC2, DigitalOcean Droplet, Linode, or Hetzner.

### Step 2.1: SSH into your server
```bash
ssh user@your-server-ip
git clone https://github.com/KNIGHT2000000/flexiProject.git
cd flexiProject
```

### Step 2.2: Launch the Stack
```bash
# Create backend environment file
copy backend\.env.example backend\.env   # Windows
# or cp backend/.env.example backend/.env # Linux

# Start PostgreSQL, FastAPI, and Nginx React frontend
docker compose up -d --build
```

### Step 2.3: Verify Running Services
```bash
docker compose ps
```
- **Web App:** `http://your-server-ip:3000`
- **FastAPI Documentation:** `http://your-server-ip:8000/docs`
- **System Health:** `http://your-server-ip:8000/api/threat/system-status`

---

## Option 3: Deploy on AWS Serverless (Enterprise Production)

Uses AWS SAM to declaratively provision a zero-maintenance serverless architecture with CloudFront CDN and API Gateway HTTP API.

### Prerequisites
1. **AWS CLI v2** configured with Administrator credentials:
   ```bash
   aws configure
   aws sts get-caller-identity
   ```
2. **AWS SAM CLI**:
   ```bash
   sam --version
   ```
3. **Node.js (v20 LTS or later)**:
   ```bash
   node --version
   ```

### Automated 1-Script Deployment

#### On Windows (PowerShell):
```powershell
.\scripts\deploy_aws.ps1 -Environment prod -Region us-east-1
```

#### On Linux / macOS (Bash):
```bash
chmod +x scripts/deploy_aws.sh scripts/deploy_frontend.sh
./scripts/deploy_aws.sh prod us-east-1
```

### What this script provisions:
1. Validates AWS credentials.
2. Packages Lambda artifacts using Python 3.12 and Mangum.
3. Deploys CloudFormation stack defined in [`template.yaml`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/template.yaml).
4. Creates private S3 origin with Origin Access Control (OAC).
5. Deploys global CloudFront distribution with TLS and SPA fallback routes.
6. Compiles React Vite assets with injected API Gateway endpoint.
7. Uploads bundle to S3 and invalidates CloudFront edge caches.

---

## Environment Variables Reference

| Variable | Target | Description | Example / Default |
| :--- | :--- | :--- | :--- |
| `DATABASE_URL` | Backend | SQLAlchemy DB connection string | `sqlite:///./phishing.db` or `postgresql://user:pass@host:5432/phishing_db` |
| `SECRET_KEY` | Backend | HMAC-SHA256 JWT signing secret key | Min 32 random characters |
| `ALGORITHM` | Backend | JWT algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Backend | JWT session lifetime | `30` |
| `VIRUSTOTAL_API_KEY` | Backend | Optional VirusTotal API key for live 70+ engine scans | `your-vt-api-key` |
| `CORS_ORIGINS` | Backend | Comma-separated allowed frontend origins | `*` or `https://phishguard.vercel.app` |
| `RATE_LIMIT` | Backend | Maximum API requests allowed in rate window | `60` |
| `RATE_WINDOW` | Backend | Rate limiting window in seconds | `60` |
| `VITE_API_URL` | Frontend | Target API gateway URL for frontend client | `https://phishguard-api.onrender.com` |

---

## Cloud Health & Diagnostics Verification

After deployment, test your live cloud instance:

1. **System Health Endpoint:**
   ```bash
   curl -s https://<YOUR_API_DOMAIN>/health
   # Expected response: {"status":"ok","version":"2.1.0","timestamp":"..."}
   ```

2. **Live Cloud Diagnostic Telemetry:**
   ```bash
   curl -s https://<YOUR_API_DOMAIN>/api/threat/system-status
   # Returns ML model status, features count, database connection & providers
   ```

3. **Live URL Inspection:**
   ```bash
   curl -X POST https://<YOUR_API_DOMAIN>/api/scan/url \
     -H "Content-Type: application/json" \
     -d '{"url": "https://google.com"}'
   ```

4. **Web UI Status Dashboard:**
   Visit `https://<YOUR_FRONTEND_DOMAIN>/system` to see real-time latency pings, ML status, threat feeds status, and database statistics directly in the browser!
