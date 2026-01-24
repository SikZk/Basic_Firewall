Write-Host "Building and starting containers in detached mode..."
docker compose up -d --build

Write-Host "Waiting for containers to be ready..."
Start-Sleep -Seconds 5

Write-Host "Opening terminal for host1..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker exec -it host1 /bin/bash"

Write-Host "Opening terminal for host2..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker exec -it host2 /bin/bash"

Write-Host "Opening terminal for firewall..."
Start-Process powershell -ArgumentList "-NoExit", "-Command", "docker exec -it firewall /bin/bash"

Write-Host "Terminals launched."
