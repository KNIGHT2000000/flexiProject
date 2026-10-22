# AI-Powered Phishing Link Detection & Threat Intelligence Platform

A professional-grade cybersecurity platform that detects phishing URLs in real time using machine learning, domain intelligence, SSL validation, VirusTotal API, QR code scanning, and DNS anti-spoofing forensics.

---

## Features

- **ML-based URL classification** — Random Forest model with 28 extracted features
- **VirusTotal API integration** — cross-reference URLs against 70+ threat engines
- **WHOIS & RDAP domain forensics** — detects newly registered domains (common in phishing)
- **SSL/TLS certificate validation** — checks expiry, issuer, and HTTPS usage
- **DNS & Anti-Spoofing Inspector** — live MX, SPF, DMARC, and authoritative nameserver security auditing
- **One-Click Forensic Report Export** — download structured JSON, Markdown, and copy to clipboard
- **System Telemetry & Health Dashboard** — live latency, ML inference state, and provider connectivity
- **QR code phishing detection** — extract and scan URLs from uploaded QR images
- **Threat dashboard** — scan history, risk charts, and detection statistics
- **Chrome extension** — real-time warnings while browsing (Manifest V3)
- **Role-based auth & guest scanning** — JWT-secured user accounts with open guest scanning
- **Cloud-ready REST API** — fully documented via `/docs` (Swagger UI) with AWS Lambda Mangum adapter

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React.js (Vite), Tailwind CSS, Recharts, Lucide Icons |
| Backend | FastAPI (Python 3.12), Pydantic v2, SQLAlchemy 2.0 |
| ML | Scikit-learn, Random Forest (28 features) |
| Database | PostgreSQL (production) / SQLite (development & serverless) |
| Auth | JWT (python-jose, bcrypt, passlib) |
| Threat Intel | VirusTotal API v3, dnspython, python-whois, pyOpenSSL |
| QR Scanning | pyzbar, Pillow |
| Cloud & Deployment | Render, Vercel, Docker, AWS SAM (Lambda + CloudFront + S3) |

---

## Quick Start

### 1. Backend

```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate      # Linux/Mac

pip install -r requirements.txt

# Train the ML model (generates synthetic data if no CSV provided)
python train_model.py
# With real dataset:
# python train_model.py --dataset ../dataset/phishing.csv

# Copy and configure environment
copy .env.example .env        # Windows
# cp .env.example .env         # Linux/Mac
# Edit .env — add your VIRUSTOTAL_API_KEY

# Start API server
python app.py
# API docs at: http://localhost:8000/docs
```

### 2. Frontend

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
# Open http://localhost:5173
```

### 3. Docker (Full Stack)

```bash
# From project root
docker compose up --build
# Frontend: http://localhost:3000
# Backend:  http://localhost:8000/docs
```

---

## Cloud Deployment

PhishGuard Cloud is ready to deploy to major cloud providers:

- **Free PaaS (Render + Vercel):** Deploy backend in 1 click using [`render.yaml`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/render.yaml) and frontend to Vercel/Netlify.
- **Docker VPS:** Deploy using Docker Compose on any Linux cloud VM (AWS EC2, DigitalOcean, Linode).
- **AWS Serverless:** Deploy to AWS Lambda, API Gateway HTTP API, S3, and CloudFront using [`scripts/deploy_aws.ps1`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/scripts/deploy_aws.ps1) or [`scripts/deploy_aws.sh`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/scripts/deploy_aws.sh).

👉 **For complete step-by-step instructions, see [`DEPLOYMENT.md`](file:///c:/Users/Mukund/Desktop/flexi-cloud/flexiProject/DEPLOYMENT.md).**

---

## Chrome Extension

1. Open Chrome → `chrome://extensions/`
2. Enable **Developer Mode**
3. Click **Load unpacked** → select `chrome-extension/` folder
4. Browse any site — the extension scans URLs automatically

---

## Dataset

Place `phishing.csv` in `dataset/` with columns: `url`, `label` (0=legit, 1=suspicious, 2=phishing).

See `dataset/README.md` for recommended sources including Kaggle and PhishTank.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan/url` | Scan a URL |
| POST | `/api/scan/qr` | Scan a QR code image |
| GET | `/api/scan/history` | Get scan history |
| GET | `/api/scan/stats` | Get detection statistics |
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Login (returns JWT) |
| GET | `/api/auth/me` | Current user info |

---

## Resume Description

> AI-Powered Phishing Link Detection and Threat Intelligence Platform — Designed and developed a machine learning-based cybersecurity solution for real-time phishing URL detection, domain reputation analysis, and threat intelligence integration. Implemented advanced security features including WHOIS analysis, SSL validation, QR code scanning, and risk-based threat reporting through an interactive web dashboard.
