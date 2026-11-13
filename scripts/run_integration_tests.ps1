param(
    # pytest arguments, for example "tests/test_response_workflow_api.py -x"
    [string]$Tests = ""
)

# Runs the backend test suite the way CI does, including the tests that need a
# real database, against a throwaway PostgreSQL container on its own Docker
# network. The database publishes no port, the live stack and its data are
# never touched, and everything created here is removed at the end.
#
# It uses the already built backend image (sentinelai-xdr-backend), so build
# the stack first if the dependencies changed.

$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path $PSScriptRoot -Parent
$Suffix = [Guid]::NewGuid().ToString("N").Substring(0, 8)
$Network = "sentinel-itest-$Suffix"
$Database = "sentinel-itest-db-$Suffix"
$Admin = "itest-only-password"
$Runtime = "itest-app-password"
$code = 1

function Invoke-Quiet([string]$Command) { cmd /c "$Command >nul 2>&1"; return $LASTEXITCODE }

try {
    if ((Invoke-Quiet "docker network create $Network") -ne 0) { throw "Could not create the test network." }
    $run = "docker run -d --name $Database --network $Network -e POSTGRES_DB=sentinel_test -e POSTGRES_USER=sentinel -e POSTGRES_PASSWORD=$Admin postgres:16-alpine"
    if ((Invoke-Quiet $run) -ne 0) { throw "Could not start the test database." }
    $ready = $false
    foreach ($attempt in 1..60) {
        if ((Invoke-Quiet "docker exec $Database psql -U sentinel -d sentinel_test -c `"select 1`"") -eq 0) { $ready = $true; break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "The test database did not become ready." }

    $common = @(
        "--rm", "--network", $Network, "--user", "0", "-v", "${ProjectRoot}:/src:ro",
        "-e", "SECRET_KEY=itest-only-signing-key-that-is-long-enough", "-e", "SENTINEL_ENV=development",
        "-e", "SENTINEL_JOB_RUNNER=inline", "-e", "POSTGRES_APP_PASSWORD=$Runtime"
    )
    $adminUrl = "postgresql+psycopg://sentinel:$Admin@${Database}:5432/sentinel_test"
    $runtimeUrl = "postgresql+psycopg://sentinel_runtime:$Runtime@${Database}:5432/sentinel_test"

    Write-Host "Migrating the test database ..."
    docker run @common -e "DATABASE_URL=$adminUrl" sentinelai-xdr-backend `
        sh -c "cp -r /src/backend /work && cd /work && alembic upgrade head >/dev/null 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "Migrations failed on the test database." }

    Write-Host "Provisioning the least-privilege roles ..."
    if ((Invoke-Quiet "docker cp `"$ProjectRoot\backend\provision_runtime_role.sql`" ${Database}:/tmp/provision.sql") -ne 0) { throw "Could not copy the provisioning script." }
    $provision = "docker exec $Database psql -v ON_ERROR_STOP=1 -U sentinel -d sentinel_test -v app_password=$Runtime -v migrator_password=itest-migrator-password -f /tmp/provision.sql"
    if ((Invoke-Quiet $provision) -ne 0) { throw "Role provisioning failed on the test database." }

    Write-Host "Running tests ..."
    $script = "cp -r /src/backend /work && cd /work && pip install --quiet --disable-pip-version-check --root-user-action=ignore pytest pytest-cov >/dev/null 2>&1; python -m pytest -q -p no:cacheprovider $Tests"
    docker run @common -e "DATABASE_URL=$runtimeUrl" -e "MFA_TEST_DATABASE_URL=$runtimeUrl" `
        -e "TENANT_TEST_DATABASE_URL=$runtimeUrl" sentinelai-xdr-backend sh -c $script
    $code = $LASTEXITCODE
}
catch {
    Write-Host "Error: $($_.Exception.Message)"
}
finally {
    Invoke-Quiet "docker rm -f $Database" | Out-Null
    Invoke-Quiet "docker network rm $Network" | Out-Null
}
exit $code
