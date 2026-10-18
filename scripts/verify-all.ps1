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
    & mvn verify -Pintegration "-Dtest.redis.executable=$RedisExecutable" -B -ntp
    if ($LASTEXITCODE -ne 0) { throw 'Full verification failed.' }
} finally { Pop-Location }
