[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Sign out every local Windows interactive session for the account running this
# script. Logging off a Windows session closes its cmd.exe and PowerShell
# processes regardless of profile loading. This does not revoke tokens or
# sessions on other computers/servers, nor SSH connections hosted by sshd.
$currentSessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId
$account = $env:USERNAME

$quser = Join-Path $env:SystemRoot 'System32\quser.exe'
$logoff = Join-Path $env:SystemRoot 'System32\logoff.exe'
$output = & $quser 2>&1
if ($LASTEXITCODE -ne 0) {
	throw "Could not enumerate Windows sessions: $($output -join ' ')"
}

$sessions = foreach ($line in ($output | Select-Object -Skip 1)) {
	# quser rows may include a leading current-session marker and may omit the
	# session name for disconnected sessions.
	if ($line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+\S+') {
		$rowAccount = ($Matches[1] -split '\\')[-1]
		if ($rowAccount -ieq $account) {
			[int]$Matches[3]
		}
	}
}

$sessions = @($sessions | Sort-Object -Unique)
if ($sessions.Count -eq 0 -or $currentSessionId -notin $sessions) {
	throw "No matching interactive sessions found for '$account'; nothing was logged off."
}

Write-Host "Sessions for '$account' that will be signed out: $($sessions -join ', ')"
Write-Host 'This closes applications and discards unsaved work. Other accounts are not affected.'
if ((Read-Host 'Type LOGOFF to continue') -cne 'LOGOFF') {
	Write-Host 'Cancelled; no sessions were ended.'
	exit 0
}

# Sign out the current session last so this script can process the remaining IDs.
$orderedSessions = @($sessions | Where-Object { $_ -ne $currentSessionId }) + $currentSessionId
$failed = @()
foreach ($id in $orderedSessions) {
	& $logoff $id
	if ($LASTEXITCODE -ne 0) {
		$failed += $id
		Write-Warning "Could not sign out session $id (exit code $LASTEXITCODE)."
	}
}

if ($failed.Count -gt 0) {
	throw "Failed to sign out session(s): $($failed -join ', '). Run elevated or contact your administrator."
}
