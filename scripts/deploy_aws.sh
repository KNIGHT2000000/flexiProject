#!/usr/bin/env bash
# PhishGuard Cloud - Full End-to-End AWS Serverless Deployment Script (Bash)
set -euo pipefail

ENVIRONMENT="${1:-prod}"
REGION="${2:-ap-southeast-2}"
STACK_NAME="phishguard-cloud-${ENVIRONMENT}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=========================================================="
echo "  PhishGuard Cloud - Automated AWS Serverless Deployment  "
echo "  Environment: ${ENVIRONMENT} | Region: ${REGION}         "
echo "=========================================================="

# 1. Prerequisite Checks
echo -e "\n[1/5] Checking prerequisites..."
command -v aws >/dev/null 2>&1 || { echo >&2 "Error: aws CLI is required."; exit 1; }
command -v sam >/dev/null 2>&1 || { echo >&2 "Error: sam CLI is required."; exit 1; }

aws sts get-caller-identity >/dev/null 2>&1 || { echo >&2 "Error: AWS credentials invalid. Run 'aws configure'."; exit 1; }
echo "  ✓ AWS Account authenticated."

# 2. Build SAM Application
echo -e "\n[2/5] Building SAM application..."
cd "${ROOT_DIR}"
sam build --template template.yaml

# 3. Deploy SAM Stack
echo -e "\n[3/5] Deploying CloudFormation stack '${STACK_NAME}'..."
EXISTING_STATUS=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "DOES_NOT_EXIST")
if [ "${EXISTING_STATUS}" = "ROLLBACK_COMPLETE" ]; then
  echo "  [*] Deleting previous rolled-back stack..."
  aws cloudformation delete-stack --stack-name "${STACK_NAME}" --region "${REGION}"
  aws cloudformation wait stack-delete-complete --stack-name "${STACK_NAME}" --region "${REGION}"
fi

sam deploy \
  --stack-name "${STACK_NAME}" \
  --region "${REGION}" \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides Environment="${ENVIRONMENT}" \
  --resolve-s3 \
  --no-fail-on-empty-changeset

# 4. Extract Stack Outputs
echo -e "\n[4/5] Extracting stack outputs..."
STACK_JSON=$(aws cloudformation describe-stacks --stack-name "${STACK_NAME}" --region "${REGION}" --output json)
API_ENDPOINT=$(echo "${STACK_JSON}" | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="ApiEndpoint") | .OutputValue')
BUCKET_NAME=$(echo "${STACK_JSON}" | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="FrontendBucketName") | .OutputValue')
DIST_ID=$(echo "${STACK_JSON}" | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="CloudFrontDistributionId") | .OutputValue')
CF_URL=$(echo "${STACK_JSON}" | jq -r '.Stacks[0].Outputs[] | select(.OutputKey=="CloudFrontDomain" or .OutputKey=="CloudFrontDomainName") | .OutputValue')

echo "  API Gateway: ${API_ENDPOINT}"
echo "  Frontend Bucket: ${BUCKET_NAME}"
echo "  CloudFront URL: https://${CF_URL}"

# 5. Build and Deploy Frontend
echo -e "\n[5/5] Deploying frontend assets to S3/CloudFront..."
"${SCRIPT_DIR}/deploy_frontend.sh" "${ENVIRONMENT}" "${API_ENDPOINT}" "${BUCKET_NAME}" "${DIST_ID}" "${REGION}"

echo -e "\n=========================================================="
echo "  Deployment Complete! https://${CF_URL}"
echo "=========================================================="
