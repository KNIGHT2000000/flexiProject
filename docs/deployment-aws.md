# PhishGuard Cloud — AWS Serverless Deployment & Operations Runbook

This document details the production-ready AWS Serverless architecture for **PhishGuard Cloud**, providing complete step-by-step instructions for provisioning infrastructure, compiling and deploying the React frontend, managing secrets, estimating operational costs, and performing clean stack teardowns.

---

## 1. Architectural Topology

PhishGuard Cloud employs a decoupled, multi-tier serverless architecture optimized for high availability, zero idle cost, and sub-100ms response times.

```mermaid
graph TD
    User["End User / Browser / Chrome Extension"]
    
    subgraph "Edge & Content Delivery Network"
        CF["Amazon CloudFront CDN<br/>(HTTPS, HTTP/2 & HTTP/3)"]
        OAC["Origin Access Control (OAC)"]
    end
    
    subgraph "Frontend Static Hosting"
        S3["Amazon S3 Private Bucket<br/>(React SPA Assets, AES256 Encrypted)"]
    end
    
    subgraph "API & Compute Layer"
        APIGW["Amazon API Gateway HTTP API<br/>(CORS, Throttling: 100 burst / 50 rate)"]
        Lambda["AWS Lambda Function (FastAPI + Mangum)<br/>(Python 3.12, 512MB, Active X-Ray Tracing)"]
        RFModel["Embedded Scikit-Learn RF Model<br/>(244 KB in-memory)"]
    end
    
    subgraph "Observability & Threat Feeds"
        CW["Amazon CloudWatch Logs<br/>(14-day retention, JSON format)"]
        VT["External Threat Intelligence<br/>(VirusTotal, RDAP, Google Safe Browsing)"]
    end

    User -->|Static Web Traffic| CF
    CF -->|Authenticated S3 Read| OAC
    OAC --> S3
    
    User -->|REST API Requests (/analyze, /api/*)| APIGW
    APIGW -->|Proxy Invocations| Lambda
    Lambda --> RFModel
    Lambda -->|Telemetry & Request IDs| CW
    Lambda -->|Live Threat Lookups (Safe Outbound)| VT
```

---

## 2. Infrastructure Resources Overview

The entire cloud infrastructure is defined declaratively as code in [`template.yaml`](file:///d:/phishing-link-detector/template.yaml) using the AWS Serverless Application Model (SAM):

| Logical Resource ID | AWS Resource Type | Configuration & Security Controls |
| :--- | :--- | :--- |
| `ApiGatewayApi` | `AWS::Serverless::HttpApi` | API Gateway v2 HTTP API with stage auto-deployment, CORS headers (`X-Request-ID` exposed), and request rate throttling (burst: 100, rate: 50). |
| `FastApiFunction` | `AWS::Serverless::Function` | Python 3.12 Lambda function wrapped with `Mangum(app, lifespan="off")`. Allocates 512 MB memory for sub-20ms cold/warm ML inference. |
| `FastApiLogGroup` | `AWS::Logs::LogGroup` | Dedicated CloudWatch log group with configurable retention (default: 14 days) preventing unbounded storage costs. |
| `FrontendBucket` | `AWS::S3::Bucket` | Fully private S3 bucket with all 4 Public Access Blocks enabled and default `AES256` server-side encryption. |
| `CloudFrontOAC` | `AWS::CloudFront::OriginAccessControl` | Modern AWS Origin Access Control (OAC) with SigV4 signing protocol. |
| `FrontendDistribution` | `AWS::CloudFront::Distribution` | Global CDN with HTTPS redirection, HTTP/2 & HTTP/3, and SPA client-side routing fallback (403/404 mapped to `/index.html`). |
| `FrontendBucketPolicy` | `AWS::S3::BucketPolicy` | Strict least-privilege policy allowing `s3:GetObject` only to the CloudFront service principal matching the distribution ARN. |

---

## 3. Prerequisites & Environment Setup

Ensure the following developer tools and credentials are installed on your deployment workstation:

1. **AWS CLI v2**:
   ```bash
   aws --version
   aws configure
   ```
   *Verify credentials:* `aws sts get-caller-identity`

2. **AWS SAM CLI**:
   ```bash
   sam --version
   ```

3. **Node.js (v20 LTS or later)** & **npm**:
   ```bash
   node -v
   npm -v
   ```

4. **Python 3.12**:
   ```bash
   python --version
   ```

---

## 4. Backend Deployment via AWS SAM

### Step 4.1: Template Validation & Linting
Validate the SAM template structure and CloudFormation specification before packaging:
```bash
# CloudFormation Linting
cfn-lint template.yaml

# SAM Native Validation
sam validate --lint
```

### Step 4.2: Build the Application Package
Compile dependencies and prepare the deployment artifact:
```bash
sam build --use-container
```
*Note: If Docker is unavailable locally, standard `sam build` works directly if Python 3.12 is installed.*

### Step 4.3: Deploy to Staging or Production
Deploy using the predefined environment profiles in [`samconfig.toml`](file:///d:/phishing-link-detector/samconfig.toml):

**Deploy Staging:**
```bash
sam deploy --config-env staging
```

**Deploy Production:**
```bash
sam deploy --config-env prod
```

**Interactive Guided Deployment (First-time setup):**
```bash
sam deploy --guided
```

### Step 4.4: Retrieve Stack Outputs
Once deployment completes, inspect the generated CloudFormation outputs:
```bash
aws cloudformation describe-stacks \
  --stack-name phishguard-cloud-prod \
  --query "Stacks[0].Outputs" \
  --output table
```

Take note of:
- `ApiEndpoint`: Base URL for API Gateway HTTP API (e.g., `https://abc123xyz.execute-api.us-east-1.amazonaws.com/prod`)
- `FrontendBucketName`: Private S3 bucket name (e.g., `phishguard-frontend-123456789012-us-east-1-prod`)
- `CloudFrontDomain`: Public CDN domain (e.g., `d111111abcdef8.cloudfront.net`)
- `CloudFrontDistributionId`: ID used for CDN cache invalidations (e.g., `E1A2B3C4D5E6F7`)

---

## 5. Frontend Build & Static Deployment Runbook

The React Single Page Application must be built with the newly provisioned `VITE_API_URL` and synced to the private S3 bucket.

### Automated Deployment (Recommended)

#### On Windows (PowerShell):
```powershell
.\scripts\deploy_frontend.ps1 -Environment prod
```

#### On Linux / macOS / CI:
```bash
chmod +x ./scripts/deploy_frontend.sh
./scripts/deploy_frontend.sh prod
```

### Manual Deployment Steps

1. **Configure Environment Variables**:
   In `frontend/`, create `.env.production`:
   ```bash
   VITE_API_URL=https://<api-id>.execute-api.<region>.amazonaws.com/prod
   ```

2. **Compile Production Assets**:
   ```bash
   cd frontend
   npm run build
   ```

3. **Synchronize Static Assets to S3**:
   - Cache immutable static bundles for 1 year:
     ```bash
     aws s3 sync dist/assets s3://<FrontendBucketName>/assets \
       --delete \
       --cache-control "public, max-age=31536000, immutable"
     ```
   - Ensure `index.html` and root files are never cached stale by browsers:
     ```bash
     aws s3 sync dist s3://<FrontendBucketName> \
       --exclude "assets/*" \
       --cache-control "no-cache, no-store, must-revalidate"
     ```

4. **Invalidate CloudFront Edge Cache**:
   ```bash
   aws cloudfront create-invalidation \
     --distribution-id <CloudFrontDistributionId> \
     --paths "/*"
   ```

---

## 6. Secrets Management & Parameter Store

In enterprise environments, secrets should never be supplied as plaintext parameters or committed to source control.

### Option A: AWS Secrets Manager Integration
Create a secret for JWT signing keys and API tokens:
```bash
aws secretsmanager create-secret \
  --name "phishguard/prod/secrets" \
  --secret-string '{"JWT_SECRET":"your-high-entropy-jwt-secret","VIRUSTOTAL_KEY":"your-vt-api-key"}'
```

In `template.yaml`, dynamic resolution references this secret without exposing values in CloudFormation templates:
```yaml
Variables:
  SECRET_KEY: '{{resolve:secretsmanager:phishguard/prod/secrets:SecretString:JWT_SECRET}}'
  VIRUSTOTAL_API_KEY: '{{resolve:secretsmanager:phishguard/prod/secrets:SecretString:VIRUSTOTAL_KEY}}'
```

### Option B: AWS Systems Manager (SSM) Parameter Store
For lower overhead, store parameters as `SecureString`:
```bash
aws ssm put-parameter \
  --name "/phishguard/prod/jwt-secret" \
  --value "your-high-entropy-jwt-secret" \
  --type "SecureString"
```

---

## 7. Cost Driver Analysis & Free Tier Compliance

PhishGuard Cloud is intentionally architected to incur **$0.00 / month** in ongoing infrastructure costs under standard low-to-medium enterprise workloads within the AWS Free Tier.

| Service | Free Tier Allowance | PhishGuard Cloud Monthly Usage | Estimated Cost |
| :--- | :--- | :--- | :--- |
| **AWS Lambda** | 1,000,000 requests/mo + 3,200,000 seconds compute (at 512MB) | ~50,000 requests / 25,000 seconds | **$0.00** |
| **Amazon API Gateway** | 1,000,000 requests/mo (first 12 mos); $1.00/1M thereafter | ~50,000 requests | **$0.00** |
| **Amazon CloudFront** | 1 TB data transfer out/mo + 10,000,000 HTTPS requests/mo (Perpetual Free Tier) | < 5 GB transfer / 100,000 requests | **$0.00** |
| **Amazon S3** | 5 GB Standard Storage + 20,000 GET requests/mo | < 20 MB static bundle storage | **$0.00** |
| **CloudWatch Logs** | 5 GB log ingestion + 14-day retention limit | < 200 MB structured JSON logs | **$0.00** |
| **Total Monthly Cost** | | | **$0.00 / month** |

---

## 8. Teardown & Clean Destruction Runbook

When tearing down a staging or testing deployment, follow these steps to prevent orphaned resources or CloudFormation deletion errors:

### Step 8.1: Empty the S3 Static Bucket
CloudFormation cannot delete an S3 bucket that contains objects:
```bash
BUCKET_NAME=$(aws cloudformation describe-stacks \
  --stack-name phishguard-cloud-staging \
  --query "Stacks[0].Outputs[?OutputKey=='FrontendBucketName'].OutputValue" \
  --output text)

aws s3 rm "s3://${BUCKET_NAME}" --recursive
```

### Step 8.2: Delete the CloudFormation Stack
```bash
sam delete --stack-name phishguard-cloud-staging --no-prompts
```

### Step 8.3: Verify Deletion
```bash
aws cloudformation describe-stacks --stack-name phishguard-cloud-staging 2>&1 | grep "does not exist"
```
All Lambda functions, log groups, API Gateway stages, S3 buckets, and CloudFront distributions are cleanly removed with zero residual costs.
