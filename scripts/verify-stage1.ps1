param()
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRoot
try {
    & mvn -pl iam-directory,iam-identity -am verify -Pintegration -B -ntp
    if ($LASTEXITCODE -ne 0) { throw 'Stage 1 verification failed.' }
} finally {
    Pop-Location
}
