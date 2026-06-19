param(
    [string]$EnvFile = ".env"
)

$ErrorActionPreference = "Stop"
$secretName = "armor-pilot-secret"
$namespace = "default"
$repoRoot = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw "Missing $EnvFile. Copy .env.example to .env and configure it first."
}

$content = Get-Content -LiteralPath $EnvFile
if ($content -match "REPLACE_WITH|<configured-|changeme|abc@123") {
    throw "$EnvFile still contains an insecure placeholder."
}

$adminUser = $content | Where-Object { $_ -match "^ADMIN_USER=.+$" }
$adminPass = $content | Where-Object { $_ -match "^ADMIN_PASS=.{12,}$" }
if (-not $adminUser -or -not $adminPass) {
    throw "$EnvFile must define ADMIN_USER and an ADMIN_PASS of at least 12 characters."
}

$secretYaml = kubectl create secret generic $secretName `
    --namespace $Namespace `
    --from-env-file=$EnvFile `
    --dry-run=client `
    -o yaml
if ($LASTEXITCODE -ne 0) {
    throw "Unable to generate Kubernetes Secret."
}

$secretYaml | kubectl apply -f -
if ($LASTEXITCODE -ne 0) {
    throw "Unable to apply Kubernetes Secret."
}

kubectl apply -f (Join-Path $repoRoot "k8s/rbac.yaml")
kubectl apply -f (Join-Path $repoRoot "k8s/deployment.yaml")
kubectl rollout restart deployment/armor-pilot --namespace $Namespace
kubectl rollout status deployment/armor-pilot --namespace $Namespace --timeout=180s

Write-Host "ArmorPilot is ready. The private environment remains in $EnvFile."
