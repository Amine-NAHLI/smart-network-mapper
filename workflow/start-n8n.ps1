# Lance ngrok en arrière-plan
Start-Process powershell -ArgumentList "-NoExit", "-Command", "ngrok http 5678 --domain=sycamore-splashy-prewar.ngrok-free.dev"

# Attends 3 secondes que ngrok démarre  
#06052005N
Start-Sleep -Seconds 3

# Lance n8n
$env:WEBHOOK_URL="https://sycamore-splashy-prewar.ngrok-free.dev/"
$env:NODE_FUNCTION_ALLOW_BUILTIN="child_process"
$env:N8N_USER_MANAGEMENT_DISABLED="true"
npx n8n 

