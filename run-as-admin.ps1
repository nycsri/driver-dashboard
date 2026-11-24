$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    Start-Process powershell -Verb RunAs -WorkingDirectory $PSScriptRoot -ArgumentList $argList
    exit
}

function Find-AppJar {
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'target') -Filter '*.jar' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*.original' -and $_.Name -notlike '*-sources.jar' -and $_.Name -notlike '*-javadoc.jar' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

try {
    $jar = Find-AppJar
    if (-not $jar) {
        Write-Host 'Building application...'
        & mvn -q -DskipTests package
        if ($LASTEXITCODE -ne 0) { throw "Maven build failed (exit $LASTEXITCODE)." }
        $jar = Find-AppJar
        if (-not $jar) { throw 'Build finished but no jar was found in target\.' }
    }

    Write-Host "Starting $($jar.Name) as Administrator..."
    & java -jar $jar.FullName
    if ($LASTEXITCODE -ne 0) { throw "Application exited with code $LASTEXITCODE." }
}
catch {
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit 1
}
