# Requires Administrator privileges to read Security Event Logs
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Please run this script as an Administrator to query Security logs."
    Exit
}

$OutputFile = "$Home\Desktop\historical_connections.txt"
$Results = @()

Write-Host "Searching Event Logs for past IP connections (Network, RDP, and SSH)..." -ForegroundColor Cyan

# 1. Query Security Log for Network Logons (Event 4624, Logon Type 3 - Network sharing, etc.)
try {
    $NetworkLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -ErrorAction SilentlyContinue
    foreach ($Event in $NetworkLogons) {
        $XML = [xml]$Event.ToXml()
        $LogonType = $XML.Event.EventData.Data | Where-Object {$_.Name -eq "LogonType"} | Select-Object -ExpandProperty "#text"
        $IpAddress = $XML.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty "#text"
        $Username  = $XML.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty "#text"

        if ($LogonType -eq "3" -and $IpAddress -and $IpAddress -ne "-" -and $IpAddress -ne "127.0.0.1" -and $IpAddress -ne "::1") {
            $Results += [PSCustomObject]@{
                Time           = $Event.TimeCreated
                IPAddress      = $IpAddress
                UserOrService  = $Username
                ConnectionType = "Network Logon (SMB/Share)"
            }
        }
    }
} catch {
    Write-Warning "Could not query Security Log. Ensure Auditing is enabled."
}

# 2. Query Remote Desktop (RDP) Operational Log (Event 1149 - Established network connection)
try {
    $RdpLogons = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Id=1149} -ErrorAction SilentlyContinue
    foreach ($Event in $RdpLogons) {
        $XML = [xml]$Event.ToXml()
        $Username  = $XML.Event.EventData.Data | Where-Object {$_.Name -eq "Param1"} | Select-Object -ExpandProperty "#text"
        $IpAddress = $XML.Event.EventData.Data | Where-Object {$_.Name -eq "Param3"} | Select-Object -ExpandProperty "#text"

        if ($IpAddress -and $IpAddress -ne "127.0.0.1" -and $IpAddress -ne "::1") {
            $Results += [PSCustomObject]@{
                Time           = $Event.TimeCreated
                IPAddress      = $IpAddress
                UserOrService  = $Username
                ConnectionType = "Remote Desktop (RDP)"
            }
        }
    }
} catch {
    Write-Warning "Could not query RDP operational logs."
}

# 3. Query OpenSSH Operational Log (Event 4 - Successful connection/authentication)
try {
    $SshLogons = Get-WinEvent -FilterHashtable @{LogName='OpenSSH/Operational'; Id=4} -ErrorAction SilentlyContinue
    foreach ($Event in $SshLogons) {
        $XML = [xml]$Event.ToXml()
        # OpenSSH packs metadata into a single Message string or raw data payload depending on version
        $Message = $Event.Message
        
        # Parse out Username and IP using basic regex matching from standard OpenSSH event strings
        if ($Message -match "Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port") {
            $Username  = $Matches[2]
            $IpAddress = $Matches[3]
        } elseif ($Message -match "Authorized\s+to\s+(\S+)\s+from\s+(\S+)\s+port") {
            $Username  = $Matches[1]
            $IpAddress = $Matches[2]
        } else {
            # Fallback string split if precise regex match drops out
            $IpAddress = $XML.Event.UserData.OpenSSH | Select-Object -ExpandProperty "SourceAddress"
            $Username  = $XML.Event.UserData.OpenSSH | Select-Object -ExpandProperty "Username"
        }

        if ($IpAddress -and $IpAddress -ne "127.0.0.1" -and $IpAddress -ne "::1") {
            $Results += [PSCustomObject]@{
                Time           = $Event.TimeCreated
                IPAddress      = $IpAddress
                UserOrService  = $Username
                ConnectionType = "Secure Shell (SSH)"
            }
        }
    }
} catch {
    Write-Warning "Could not query OpenSSH operational logs. Ensure Windows OpenSSH feature is running."
}

# Output Consolidated Results to Text File
if ($Results) {
    $Results | Sort-Object Time -Descending | Format-Table -AutoSize | Out-File -FilePath $OutputFile -Width 300
    Write-Host "Success! Consolidated connection history saved to: $OutputFile" -ForegroundColor Green
} else {
    Write-Host "No historical connections found for SMB, RDP, or SSH." -ForegroundColor Yellow
}
