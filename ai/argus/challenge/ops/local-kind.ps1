[CmdletBinding()]
param(
    [ValidateSet("bootstrap", "cleanup")]
    [string] $Action = "bootstrap",
    [string] $InstanceId = "",
    [string] $NamespacePrefix = "",
    [ValidateRange(600, 3600)]
    [int] $TokenDurationSeconds = 3600
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$secretsRoot = Join-Path $repoRoot ".argus-local-kind\secrets"
$localRoot = Join-Path $repoRoot ".argus-local-kind"

if (-not $PSBoundParameters.ContainsKey("InstanceId")) {
    $InstanceId = if ($env:INSTANCE_ID) { $env:INSTANCE_ID } else { "team-a" }
}
if (-not $PSBoundParameters.ContainsKey("NamespacePrefix")) {
    $NamespacePrefix = if ($env:ARGUS_K8S_NAMESPACE_PREFIX) { $env:ARGUS_K8S_NAMESPACE_PREFIX } else { "argus" }
}

if ($InstanceId -notmatch "^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$") {
    throw "INSTANCE_ID is invalid"
}
if ($NamespacePrefix -notmatch "^[a-z](?:[a-z0-9-]{0,18}[a-z0-9])?$") {
    throw "ARGUS_K8S_NAMESPACE_PREFIX is invalid"
}

function Invoke-KindKubectl {
    param([Parameter(Mandatory)][string[]] $Arguments)

    & kubectl @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "kubectl command failed"
    }
}

function Assert-KindContext {
    $contexts = @(& kubectl config get-contexts -o name 2>$null)
    if ($LASTEXITCODE -ne 0 -or $contexts -notcontains "kind-argus") {
        throw "kubectl context kind-argus does not exist"
    }

    $current = (& kubectl config current-context 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $current -ne "kind-argus") {
        throw "refusing to operate outside the kind-argus context"
    }

    & docker network inspect kind *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker network kind does not exist"
    }
    & docker inspect argus-control-plane *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "kind control-plane container argus-control-plane does not exist"
    }
}

function Get-ArgusNamespace {
    Push-Location (Join-Path $repoRoot "app")
    try {
        $pythonCode = "from argus.kubernetes import namespace_for_instance; print(namespace_for_instance('$InstanceId', '$NamespacePrefix'))"
        $python = Get-Command python -ErrorAction SilentlyContinue
        if ($null -eq $python) {
            $python = Get-Command py -ErrorAction SilentlyContinue
            if ($null -eq $python) {
                throw "Python is required to derive the ARGUS namespace"
            }
            $output = & $python.Source -3 -c $pythonCode 2>&1
        } else {
            $output = & $python.Source -c $pythonCode 2>&1
        }
        if ($LASTEXITCODE -ne 0) {
            throw "ARGUS namespace derivation failed"
        }
        $namespace = ($output | Out-String).Trim()
        if ($namespace -notmatch "^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$") {
            throw "ARGUS namespace derivation returned an invalid namespace"
        }
        return $namespace
    } finally {
        Pop-Location
    }
}

function Get-KindCaBytes {
    $json = (& kubectl config view --raw --minify -o json | Out-String) | ConvertFrom-Json
    $contextName = $json.'current-context'
    $context = @($json.contexts | Where-Object { $_.name -eq $contextName })[0]
    $clusterName = $context.context.cluster
    $cluster = @($json.clusters | Where-Object { $_.name -eq $clusterName })[0].cluster
    $caData = $cluster.'certificate-authority-data'
    if ($caData) {
        return [Convert]::FromBase64String($caData)
    }
    if ($cluster.'certificate-authority') {
        return [IO.File]::ReadAllBytes($cluster.'certificate-authority')
    }
    throw "kind kubeconfig has no certificate authority"
}

function Render-Contract {
    param([Parameter(Mandatory)][string] $Namespace)

    $templatePath = Join-Path $repoRoot "ops\kubernetes\team-namespace.yaml"
    $manifest = [IO.File]::ReadAllText($templatePath)
    $createdAt = [DateTime]::UtcNow.ToString("o")
    $expiresAt = [DateTime]::UtcNow.AddSeconds($TokenDurationSeconds).ToString("o")
    $values = @{
        '${ARGUS_NAMESPACE}' = $Namespace
        '${ARGUS_INSTANCE_ID}' = $InstanceId
        '${ARGUS_CREATED_AT}' = $createdAt
        '${ARGUS_EXPIRES_AT}' = $expiresAt
        '${ARGUS_VERIFICATION_RESULT}' = "local-kind-verification"
        '${ARGUS_DEPLOYER_SERVICE_ACCOUNT}' = "argus-deployer"
    }
    foreach ($entry in $values.GetEnumerator()) {
        $manifest = $manifest.Replace($entry.Key, [string] $entry.Value)
    }
    return $manifest
}

Assert-KindContext
$namespace = Get-ArgusNamespace

if ($Action -eq "cleanup") {
    Invoke-KindKubectl @("delete", "namespace", $namespace, "--ignore-not-found=true") | Out-Null
    if (Test-Path -LiteralPath $localRoot) {
        Remove-Item -LiteralPath $localRoot -Recurse -Force
    }
    Write-Host "Cleaned local ARGUS kind namespace $namespace and local secrets."
    exit 0
}

New-Item -ItemType Directory -Path $secretsRoot -Force | Out-Null
$manifestPath = Join-Path $secretsRoot "team-namespace.rendered.yaml"
$caPath = Join-Path $secretsRoot "k8s-ca.crt"
$tokenPath = Join-Path $secretsRoot "k8s-deployer-token"
try {
    [IO.File]::WriteAllText($manifestPath, (Render-Contract $namespace))
    Invoke-KindKubectl @("apply", "-f", $manifestPath) | Out-Null
    [IO.File]::WriteAllBytes($caPath, (Get-KindCaBytes))

    # Capture the short-lived credential; never emit it or include it in a command line shown to the user.
    $tokenOutput = @(& kubectl create token argus-deployer -n $namespace "--duration=$($TokenDurationSeconds)s" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "argus-deployer TokenRequest failed"
    }
    $token = ($tokenOutput | Out-String).Trim()
    if (-not $token -or $token -match "\s") {
        throw "argus-deployer TokenRequest returned an invalid token"
    }
    [IO.File]::WriteAllText($tokenPath, $token + [Environment]::NewLine)
} finally {
    if (Test-Path -LiteralPath $manifestPath) {
        Remove-Item -LiteralPath $manifestPath -Force
    }
}

Write-Host "Bootstrapped $namespace for INSTANCE_ID=$InstanceId."
Write-Host "CA and deployer credential were written under .argus-local-kind\secrets for Deployment only."
