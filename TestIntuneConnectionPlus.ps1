<#
.SYNOPSIS
    Robust Intune / Autopilot / Entra connectivity test.
.DESCRIPTION
    Tests DNS + TCP:443 + HTTPS for a curated list of Microsoft device-enrolment endpoints.
    Logs to: C:\Windows\Temp\Test-IntuneConnectivityPlus.log
    Exports: C:\Windows\Temp\Test-IntuneConnectivityPlus.csv
             C:\Windows\Temp\Test-IntuneConnectivityPlus.json
    Returns non-zero exit code if critical endpoints fail.
.NOTES
    Designed to run in ESP / OOBE (no UI), or as Intune proactive remediation.
#>

param(
    [string]$LogPath = "C:\Windows\Temp\Test-IntuneConnectivityPlus.log",
    [string]$CsvPath = "C:\Windows\Temp\Test-IntuneConnectivityPlus.csv",
    [string]$JsonPath = "C:\Windows\Temp\Test-IntuneConnectivityPlus.json",
    [switch]$VerboseMode
)

# ====== logging ======
"===== Test-IntuneConnectivityPlus started $(Get-Date) =====" | Out-File -FilePath $LogPath -Encoding utf8

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "[$ts][$Level] $Message"
    $line | Out-File -FilePath $LogPath -Append -Encoding utf8
    if ($VerboseMode) { Write-Host $line }
}

# ====== helper: run under system context? ======
$runningAsSystem = $false
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($id.Name -eq "NT AUTHORITY\SYSTEM") { $runningAsSystem = $true }
}
catch {
    Write-Log "Could not determine account: $($_.Exception.Message)" "WARN"
}

if ($runningAsSystem) {
    Write-Log "Running under SYSTEM context."
} else {
    Write-Log "Running under USER context. NOTE: ESP/MDM uses SYSTEM, so results may differ." "WARN"
}

# ====== collect proxy info ======
Write-Log "---- Proxy information -----"
try {
    $winhttp = netsh winhttp show proxy 2>&1
    $winhttp | Out-File -FilePath $LogPath -Append -Encoding utf8
    Write-Log "WinHTTP proxy captured."
} catch {
    Write-Log "Failed to read WinHTTP proxy: $($_.Exception.Message)" "WARN"
}

try {
    $userProxy = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy("https://login.microsoftonline.com")
    Write-Log "User/WinINET proxy for https://login.microsoftonline.com -> $userProxy"
} catch {
    Write-Log "Failed to resolve user proxy: $($_.Exception.Message)" "WARN"
}

# ====== endpoint list ======
# Core identity / device registration
$coreEndpoints = @(
    "login.microsoftonline.com",
    "device.login.microsoftonline.com",
    "enterpriseregistration.windows.net",
    "autologon.microsoftazuread-sso.com"
)

# Intune / MDM enrolment (generic global + some common FEFs; add your tenant’s region here)
$intuneEndpoints = @(
    "enrollment.manage.microsoft.com",
    "portal.manage.microsoft.com",
    "manage.microsoft.com",
    "fef.msua01.manage.microsoft.com",
    "fef.msua02.manage.microsoft.com",
    "fef.msua03.manage.microsoft.com"
)

# Autopilot
$autopilotEndpoints = @(
    "ztd.dds.microsoft.com",
    "cs.dds.microsoft.com",
    "autopilot.microsoft.com"
)

# Connectivity / OS
$connectivityEndpoints = @(
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "ctldl.windowsupdate.com"
)

# Defender / service control (optional but useful to prove SSL via corp proxy)
$optionalEndpoints = @(
    "winatp-gw-cus.microsoft.com",
    "winatp-gw-eus.microsoft.com"
)

$allEndpoints = $coreEndpoints + $intuneEndpoints + $autopilotEndpoints + $connectivityEndpoints + $optionalEndpoints
$allEndpoints = $allEndpoints | Select-Object -Unique

Write-Log "Total endpoints to test: $($allEndpoints.Count)"

# ====== helper: TLS test via Invoke-WebRequest ======
function Test-Https {
    param(
        [Parameter(Mandatory)][string]$HostName
    )
    $uri = "https://$HostName"
    try {
        $r = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 12
        return @{
            Success   = $true
            Code      = $r.StatusCode
            Exception = $null
        }
    } catch {
        return @{
            Success   = $false
            Code      = $null
            Exception = $_.Exception.Message
        }
    }
}

# ====== helper: TCP 443 test ======
function Test-Tcp443 {
    param([string]$HostName)
    try {
        $tnc = Test-NetConnection -ComputerName $HostName -Port 443 -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        return @{
            Success = [bool]$tnc.TcpTestSucceeded
            Raw     = $tnc
        }
    } catch {
        return @{
            Success = $false
            Raw     = $_.Exception.Message
        }
    }
}

# ====== helper: DNS test ======
function Test-Dns {
    param([string]$HostName)
    try {
        $dns = Resolve-DnsName -Name $HostName -ErrorAction Stop
        return @{
            Success = $true
            IP      = $dns[0].IPAddress
        }
    } catch {
        return @{
            Success = $false
            IP      = $null
            Error   = $_.Exception.Message
        }
    }
}

# ====== main test loop ======
$results = New-Object System.Collections.Generic.List[Object]

foreach ($ep in $allEndpoints) {
    Write-Log "Testing $ep ..."
    $dns   = Test-Dns -HostName $ep
    $tcp   = $null
    $https = $null

    if ($dns.Success) {
        $tcp = Test-Tcp443 -HostName $ep
        $https = Test-Https -HostName $ep
    } else {
        Write-Log "DNS failed for $ep- $($dns.Error)" "WARN"
    }

    $overall =
        if (-not $dns.Success) { "FAIL-DNS" }
        elseif (-not $tcp.Success) { "FAIL-TCP443" }
        elseif (-not $https.Success) { "FAIL-HTTPS" }
        else { "OK" }

    $obj = [pscustomobject]@{
        TimeStamp   = (Get-Date)
        Endpoint    = $ep
        DnsOK       = $dns.Success
        DnsIP       = $dns.IP
        Tcp443OK    = if ($tcp) { $tcp.Success } else { $false }
        HttpsOK     = if ($https) { $https.Success } else { $false }
        HttpCode    = if ($https) { $https.Code } else { $null }
        HttpsError  = if ($https) { $https.Exception } else { $null }
        Overall     = $overall
    }

    $results.Add($obj) | Out-Null
    Write-Log "$ep -> $overall"
}

# ====== write CSV / JSON ======
try {
    $results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV written to $CsvPath"
} catch {
    Write-Log "Failed to write CSV: $($_.Exception.Message)" "WARN"
}

try {
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $JsonPath -Encoding utf8
    Write-Log "JSON written to $JsonPath"
} catch {
    Write-Log "Failed to write JSON: $($_.Exception.Message)" "WARN"
}

# ====== summary to screen ======
$failures = $results | Where-Object { $_.Overall -ne "OK" }
$criticalCount = $failures.Count

Write-Host ""
Write-Host "========= Intune / Autopilot Connectivity Summary ========="
$results | Select-Object Endpoint, Overall, DnsOK, Tcp443OK, HttpsOK | Format-Table -AutoSize
Write-Host "============================================================="
Write-Host "Log  : $LogPath"
Write-Host "CSV  : $CsvPath"
Write-Host "JSON : $JsonPath"

if ($criticalCount -gt 0) {
    Write-Host ""
    Write-Host "FAILED endpoints:" -ForegroundColor Red
    $failures | Select-Object Endpoint, Overall, HttpsError | Format-Table -AutoSize
    Write-Log "Connectivity test completed with $criticalCount failures." "WARN"
    exit 1
} else {
    Write-Log "Connectivity test completed successfully. All endpoints OK."
    exit 0
}
