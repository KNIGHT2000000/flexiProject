# PhishGuard Cloud - Full End-to-End AWS Serverless Deployment Script
# Provisions API Gateway, Lambda Backend, S3 Private Bucket, and CloudFront CDN.
# Usage:
#   .\scripts\deploy_aws.ps1 -Environment prod -Region us-east-1

param (
    [string]$Environment = "prod",
    [string]$Region = "us-east-1",
    [string]$StackName = "phishguard-cloud-$Environment"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  PhishGuard Cloud - Automated AWS Serverless Deployment  " -ForegroundColor Cyan
Write-Host "  Environment: $Environment | Region: $Region             " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Prerequisite Validation
Write-Host "`n[1/5] Checking deployment prerequisites..." -ForegroundColor Yellow

if (-not (Get-Command aws -ErrorAction SilentlyContinue)) {
    Write-Error "AWS CLI is not installed or not in PATH. Please install from: https://aws.amazon.com/cli/"
}

if (-not (Get-Command sam -ErrorAction SilentlyContinue)) {
    Write-Error "AWS SAM CLI is not installed or not in PATH. Please install from: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html"
}

try {
    $callerIdentity = aws sts get-caller-identity --output json | ConvertFrom-Json
    Write-Host "  ✓ AWS Account authenticated: $($callerIdentity.Account) ($($callerIdentity.Arn))" -ForegroundColor Green
} catch {
    Write-Error "AWS authentication failed. Run 'aws configure' to set up valid credentials."
}

# 2. Build SAM Application
Write-Host "`n[2/5] Building SAM application artifacts..." -ForegroundColor Yellow
Push-Location (Join-Path $PSScriptRoot "..")
try {
    sam build --template template.yaml
    Write-Host "  ✓ SAM build completed successfully." -ForegroundColor Green
} catch {
    Pop-Location
    Write-Error "SAM build failed: $_"
}

# 3. Deploy CloudFormation Stack
Write-Host "`n[3/5] Deploying CloudFormation stack '$StackName'..." -ForegroundColor Yellow
try {
    sam deploy `
        --stack-name $StackName `
        --region $Region `
        --capabilities CAPABILITY_IAM `
        --parameter-overrides Environment=$Environment `
        --resolve-s3 `
        --no-fail-on-empty-changeset

    Write-Host "  ✓ Backend SAM stack deployed successfully." -ForegroundColor Green
} catch {
    Pop-Location
    Write-Error "SAM deployment failed: $_"
}

# 4. Extract Stack Outputs
Write-Host "`n[4/5] Extracting CloudFormation stack outputs..." -ForegroundColor Yellow
$stackJson = aws cloudformation describe-stacks --stack-name $StackName --region $Region --output json | ConvertFrom-Json
$outputs = $stackJson.Stacks[0].Outputs

$apiEndpoint = ($outputs | Where-Object { $_.OutputKey -eq "ApiEndpoint" }).OutputValue
$bucketName = ($outputs | Where-Object { $_.OutputKey -eq "FrontendBucketName" }).OutputValue
$distributionId = ($outputs | Where-Object { $_.OutputKey -eq "CloudFrontDistributionId" }).OutputValue
$cloudFrontUrl = ($outputs | Where-Object { $_.OutputKey -eq "CloudFrontDomainName" }).OutputValue

Write-Host "  Deployed Endpoints:" -ForegroundColor Cyan
Write-Host "    API Gateway URL:     $apiEndpoint"
Write-Host "    Frontend S3 Bucket:  $bucketName"
Write-Host "    CloudFront Dist ID:  $distributionId"
Write-Host "    CloudFront Web URL:  https://$cloudFrontUrl"

# 5. Build & Deploy Frontend to S3 and CloudFront
Write-Host "`n[5/5] Building and deploying React frontend..." -ForegroundColor Yellow
Pop-Location
& (Join-Path $PSScriptRoot "deploy_frontend.ps1") `
    -Environment $Environment `
    -ApiEndpoint $apiEndpoint `
    -BucketName $bucketName `
    -DistributionId $distributionId `
    -Region $Region

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host "  PhishGuard Cloud Deployment Complete!                   " -ForegroundColor Green
Write-Host "  Web Application:  https://$cloudFrontUrl                " -ForegroundColor Green
Write-Host "  Swagger API Docs: $apiEndpoint/docs                     " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
