# Build — and optionally push — the review-api image, from this folder only.
#
#   powershell -ExecutionPolicy Bypass -File backend\build.ps1
#   powershell -ExecutionPolicy Bypass -File backend\build.ps1 -Tag 1.2.0
#   powershell -ExecutionPolicy Bypass -File backend\build.ps1 -Registry ghcr.io/me -Push
#
# REGISTRY and TAG can also come from the environment. Pushing needs a prior
# `docker login <registry>`: this script never handles credentials.

param(
    [string]$Registry = $env:REGISTRY,
    [string]$Tag = $(if ($env:TAG) { $env:TAG } else { "latest" }),
    [switch]$Push
)

$ErrorActionPreference = "Stop"
$Image = "review-api"

# Refuse before building, not after: an unqualified name would be pushed to
# Docker Hub's official "library" namespace, which nobody here can write to.
if ($Push -and -not $Registry) {
    throw "-Push needs -Registry (e.g. ghcr.io/<owner> or docker.io/<user>)"
}

$Ref = if ($Registry) { "$($Registry.TrimEnd('/'))/${Image}:$Tag" } else { "${Image}:$Tag" }

Push-Location -LiteralPath $PSScriptRoot
try {
    # The shared review engine and the deterministic scanner tier both live
    # outside this folder; each arrives as a named build context.
    docker build --build-context "mcp-server=./mcp-server" `
                 --build-context "scanner=./scanner" `
                 --tag $Ref .
    if ($LASTEXITCODE -ne 0) { throw "docker build failed (exit $LASTEXITCODE)" }
    Write-Host "built:  $Ref"

    if ($Push) {
        docker push $Ref
        if ($LASTEXITCODE -ne 0) {
            throw "push failed. Logged in? docker login $($Registry.Split('/')[0])"
        }
        Write-Host "pushed: $Ref"
    }
}
finally {
    Pop-Location
}
