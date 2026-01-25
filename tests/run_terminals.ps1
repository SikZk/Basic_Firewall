$ErrorActionPreference = "Stop"

Write-Host "Building and starting containers in detached mode..."
docker compose up -d --build

Write-Host "Waiting for containers to be ready..."
Start-Sleep -Seconds 5

function Open-Terminal {
    param (
        [string]$ContainerName
    )
    Write-Host "Opening terminal for $ContainerName..."
    # Start a new PowerShell window that enters the container
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker exec -it $ContainerName /bin/bash"
}

Open-Terminal "host1"
Open-Terminal "host2"
Open-Terminal "firewall"

Write-Host "Terminals launched."

# Follow the logs of the firewall container
docker compose logs -f firewall
