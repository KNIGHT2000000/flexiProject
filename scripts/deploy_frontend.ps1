# PhishGuard Cloud - Frontend Build & S3/CloudFront Deployment Script
# Usage:
#   .\scripts\deploy_frontend.ps1 -Environment staging
#   .\scripts\deploy_frontend.ps1 -Environment prod -ApiEndpoint "https://api-id.execute-api.us-east-1.amazonaws.com/prod"

param (
    [string]$Environment = "staging",
    [string]$ApiEndpoint = "",
    [string]$BucketName = "",
    [string]$DistributionId = "",
    [string]$Region = "ap-southeast-2"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " PhishGuard Cloud Frontend Deployment ($Environment)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$StackName = "phishguard-cloud-$Environment"
$FrontendDir = Join-Path $PSScriptRoot "..\frontend"

# 1. Resolve CloudFormation stack outputs if not explicitly supplied
if (-not $BucketName -or -not $DistributionId -or -not $ApiEndpoint) {
    Write-Host "[*] Querying CloudFormation stack '$StackName' for deployment targets..." -ForegroundColor Yellow
    try {
        $stackJson = aws cloudformation describe-stacks --stack-name $StackName --region $Region --output json | ConvertFrom-Json
        $outputs = $stackJson.Stacks[0].Outputs

        if (-not $BucketName) {
            $BucketName = ($outputs | Where-Object { $_.OutputKey -eq "FrontendBucketName" }).OutputValue
        }
        if (-not $DistributionId) {
            $DistributionId = ($outputs | Where-Object { $_.OutputKey -eq "CloudFrontDistributionId" }).OutputValue
        }
        if (-not $ApiEndpoint) {
            $ApiEndpoint = ($outputs | Where-Object { $_.OutputKey -eq "ApiEndpoint" }).OutputValue
        }
    } catch {
        Write-Warning "Could not automatically fetch outputs from stack '$StackName'."
        Write-Warning "Ensure AWS credentials are configured and the SAM stack is deployed."
    }
}

Write-Host "Target Configuration:"
Write-Host "  Stack Name:      $StackName"
Write-Host "  Frontend Bucket: $BucketName"
Write-Host "  Distribution ID: $DistributionId"
Write-Host "  API Endpoint:    $ApiEndpoint"

if (-not $BucketName) {
    Write-Error "Deployment aborted: S3 Frontend Bucket name must be provided via -BucketName or CloudFormation output."
}

# 2. Configure environment variables for build
Push-Location $FrontendDir
try {
    if ($ApiEndpoint) {
        Write-Host "[*] Configuring VITE_API_URL=$ApiEndpoint" -ForegroundColor Green
        $env:VITE_API_URL = $ApiEndpoint
    }

    # 3. Build React static bundle
    Write-Host "[*] Compiling React static assets with Vite..." -ForegroundColor Yellow
    npm run build

    $DistDir = Join-Path $FrontendDir "dist"
    if (-not (Test-Path $DistDir)) {
        Write-Error "Build output directory 'dist' was not found."
    }

    # 4. Upload static assets to S3
    Write-Host "[*] Syncing immutable assets to s3://$BucketName/assets with 1-year cache headers..." -ForegroundColor Yellow
    aws s3 sync "$DistDir/assets" "s3://$BucketName/assets" --delete --cache-control "public, max-age=31536000, immutable"

    Write-Host "[*] Syncing root HTML & manifests with no-cache headers..." -ForegroundColor Yellow
    aws s3 sync "$DistDir" "s3://$BucketName" --exclude "assets/*" --cache-control "no-cache, no-store, must-revalidate"

    # 5. Invalidate CloudFront CDN Cache
    if ($DistributionId) {
        Write-Host "[*] Creating CloudFront cache invalidation for distribution $DistributionId..." -ForegroundColor Yellow
        $invalidation = aws cloudfront create-invalidation --distribution-id $DistributionId --paths "/*" --output json | ConvertFrom-Json
        Write-Host "[+] CloudFront invalidation created: $($invalidation.Invalidation.Id)" -ForegroundColor Green
    } else {
        Write-Warning "No Distribution ID provided; CloudFront cache invalidation skipped."
    }

    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " Frontend deployment to $Environment completed successfully!" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
} finally {
    Pop-Location
}
