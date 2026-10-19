param([string]$RedisExecutable = $env:UNIPASS_TEST_REDIS_EXECUTABLE)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RedisExecutable)) {
    $redisCommand = Get-Command redis-server -ErrorAction SilentlyContinue
    if ($redisCommand) { $RedisExecutable = $redisCommand.Source }
}
if ([string]::IsNullOrWhiteSpace($RedisExecutable)) {
    throw 'Set UNIPASS_TEST_REDIS_EXECUTABLE or pass -RedisExecutable with the redis-server executable path.'
}
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $wrapper = if ($IsWindows) { '.\gradlew.bat' } else { './gradlew' }
    & $wrapper --no-daemon clean build "-PtestRedisExecutable=$RedisExecutable"
    if ($LASTEXITCODE -ne 0) { throw 'Gradle verification failed.' }
} finally { Pop-Location }
