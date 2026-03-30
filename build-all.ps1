param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest
$repoRoot = $PSScriptRoot

function Invoke-DotNet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    & dotnet $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $Command failed with exit code $LASTEXITCODE."
    }
}

Invoke-DotNet restore @((Join-Path $repoRoot "Krypton.Core\Krypton.Core.csproj"))
Invoke-DotNet restore @((Join-Path $repoRoot "Krypton.Pipeline\Krypton.Pipeline.csproj"))
# Workaround for intermittent static-graph restore/build failures on Krypton.csproj.
Invoke-DotNet msbuild @((Join-Path $repoRoot "Krypton\Krypton.csproj"), "/t:Restore", "/m:1")

Invoke-DotNet build @((Join-Path $repoRoot "Krypton.Core\Krypton.Core.csproj"), "-c", $Configuration, "--no-restore")
Invoke-DotNet build @((Join-Path $repoRoot "Krypton.Pipeline\Krypton.Pipeline.csproj"), "-c", $Configuration, "--no-restore")
Invoke-DotNet msbuild @((Join-Path $repoRoot "Krypton\Krypton.csproj"), "/t:Build", "/p:Configuration=$Configuration", "/m:1")

Write-Host "Build completed for configuration '$Configuration'."
