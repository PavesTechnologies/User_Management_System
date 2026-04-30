# Stop the script if any native PowerShell command fails
$ErrorActionPreference = "Stop"
 
# Helper function to check if the last external command succeeded
function Check-ExitCode {
    if ($LASTEXITCODE -ne 0) {
        Write-Host "`n[!] ERROR: Command failed with exit code $LASTEXITCODE. Aborting deployment." -ForegroundColor Red
        exit $LASTEXITCODE
    }
}
 
Write-Host "--- Starting Deployment for intranet-ums ---" -ForegroundColor Cyan
 
# 1. Build the Docker Image and Run Containers
Write-Host "Step 1: Building image and starting services..." -ForegroundColor Yellow
docker compose up --build -d
Check-ExitCode
 
# 2. Push to Docker Hub
# Note: Ensure the 'image' name in your docker-compose.yml is set to 'pavesadmin/intranet-ums:latest'
Write-Host "Step 2: Pushing image to Docker Hub..." -ForegroundColor Yellow
docker push pavesadmin/intranet-ums:latest
Check-ExitCode
 
Write-Host "--- Deployment Successful! ---" -ForegroundColor Green