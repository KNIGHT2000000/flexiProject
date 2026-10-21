#!/usr/bin/env bash
# PhishGuard Cloud - Frontend Build & S3/CloudFront Deployment Script
# Usage:
#   ./scripts/deploy_frontend.sh [staging|prod] [API_ENDPOINT] [BUCKET_NAME] [DISTRIBUTION_ID] [REGION]

set -euo pipefail

ENVIRONMENT="${1:-staging}"
API_ENDPOINT="${2:-}"
BUCKET_NAME="${3:-}"
DISTRIBUTION_ID="${4:-}"
REGION="${5:-us-east-1}"

STACK_NAME="phishguard-cloud-${ENVIRONMENT}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="${SCRIPT_DIR}/../frontend"

echo "=========================================================="
echo " PhishGuard Cloud Frontend Deployment (${ENVIRONMENT})"
echo "=========================================================="

# 1. Resolve CloudFormation stack outputs if missing
if [[ -z "${BUCKET_NAME}" || -z "${DISTRIBUTION_ID}" || -z "${API_ENDPOINT}" ]]; then
    echo "[*] Querying CloudFormation stack '${STACK_NAME}' for deployment targets..."
    if command -v aws &> /dev/null; then
        OUTPUTS=$(aws cloudformation describe-stacks \
            --stack-name "${STACK_NAME}" \
            --region "${REGION}" \
            --query "Stacks[0].Outputs" \
            --output json 2>/dev/null || echo "[]")

        if [[ -z "${BUCKET_NAME}" ]]; then
            BUCKET_NAME=$(echo "${OUTPUTS}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(next((o['OutputValue'] for o in data if o['OutputKey']=='FrontendBucketName'), ''))")
        fi
        if [[ -z "${DISTRIBUTION_ID}" ]]; then
            DISTRIBUTION_ID=$(echo "${OUTPUTS}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(next((o['OutputValue'] for o in data if o['OutputKey']=='CloudFrontDistributionId'), ''))")
        fi
        if [[ -z "${API_ENDPOINT}" ]]; then
            API_ENDPOINT=$(echo "${OUTPUTS}" | python3 -c "import sys, json; data=json.load(sys.stdin); print(next((o['OutputValue'] for o in data if o['OutputKey']=='ApiEndpoint'), ''))")
        fi
    fi
fi

echo "Target Configuration:"
echo "  Stack Name:      ${STACK_NAME}"
echo "  Frontend Bucket: ${BUCKET_NAME}"
echo "  Distribution ID: ${DISTRIBUTION_ID}"
echo "  API Endpoint:    ${API_ENDPOINT}"

if [[ -z "${BUCKET_NAME}" ]]; then
    echo "ERROR: S3 Frontend Bucket name must be provided as argument 3 or via CloudFormation outputs."
    exit 1
fi

# 2. Build React static bundle
cd "${FRONTEND_DIR}"
if [[ -n "${API_ENDPOINT}" ]]; then
    export VITE_API_URL="${API_ENDPOINT}"
fi

echo "[*] Compiling React static assets with Vite..."
npm run build

DIST_DIR="${FRONTEND_DIR}/dist"
if [[ ! -d "${DIST_DIR}" ]]; then
    echo "ERROR: Build output directory 'dist' was not found."
    exit 1
fi

# 3. Upload static assets to S3
echo "[*] Syncing immutable assets to s3://${BUCKET_NAME}/assets with 1-year cache headers..."
aws s3 sync "${DIST_DIR}/assets" "s3://${BUCKET_NAME}/assets" \
    --delete \
    --cache-control "public, max-age=31536000, immutable"

echo "[*] Syncing root HTML & manifests with no-cache headers..."
aws s3 sync "${DIST_DIR}" "s3://${BUCKET_NAME}" \
    --exclude "assets/*" \
    --cache-control "no-cache, no-store, must-revalidate"

# 4. Invalidate CloudFront CDN Cache
if [[ -n "${DISTRIBUTION_ID}" ]]; then
    echo "[*] Creating CloudFront cache invalidation for distribution ${DISTRIBUTION_ID}..."
    INVALIDATION_ID=$(aws cloudfront create-invalidation \
        --distribution-id "${DISTRIBUTION_ID}" \
        --paths "/*" \
        --query "Invalidation.Id" \
        --output text)
    echo "[+] CloudFront invalidation created: ${INVALIDATION_ID}"
fi

echo "=========================================================="
echo " Frontend deployment to ${ENVIRONMENT} completed successfully!"
echo "=========================================================="
