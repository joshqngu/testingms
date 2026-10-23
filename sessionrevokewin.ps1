[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# List local Windows interactive sessions and allow selected sessions to be
# signed out. This does not affect sessions on other computers/servers or SSH.
$currentSessionId = (Get-Process -Id $PID -ErrorAction Stop).SessionId

$quser = Join-Path $env:SystemRoot 'System32\quser.exe'
$logoff = Join-Path $env:SystemRoot 'System32\logoff.exe'
$output = & $quser 2>&1
if ($LASTEXITCODE -ne 0) {
	throw "Could not enumerate Windows sessions: $($output -join ' ')"
}

$sessions = foreach ($line in ($output | Select-Object -Skip 1)) {
	# quser rows may include a leading current-session marker and may omit the
	# session name for disconnected sessions.
	if ($line -match '^\s*>?\s*(\S+)\s+(?:(\S+)\s+)?(\d+)\s+(\S+)') {
		[pscustomobject]@{
			User        = $Matches[1]
			SessionName = $Matches[2]
			Id          = [int]$Matches[3]
			State       = $Matches[4]
		}
	}
}

if (@($sessions).Count -eq 0) {
	throw 'No interactive Windows sessions were found.'
}

Write-Host 'Logged-in Windows sessions:'
$sessions | Format-Table User, SessionName, Id, State -AutoSize | Out-Host
$choice = Read-Host 'Enter session IDs separated by commas, or ALL to select every session'
if ($choice -ceq 'ALL') {
	$selected = @($sessions)
}
else {
	$ids = @($choice -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
	if ($ids.Count -eq 0 -or @($ids | Where-Object { $_ -notmatch '^\d+$' }).Count -gt 0) {
		throw 'Enter one or more listed session IDs, or ALL.'
	}
	$requestedIds = @($ids | ForEach-Object { [int]$_ } | Sort-Object -Unique)
	$selected = @($sessions | Where-Object { $_.Id -in $requestedIds })
	if ($selected.Count -ne $requestedIds.Count) {
		throw 'One or more IDs were not listed; no sessions were signed out.'
	}
}

Write-Host "Sessions selected for sign-out: $(($selected | ForEach-Object { "$($_.User) (ID $($_.Id))" }) -join ', ')"
if ((Read-Host 'Type LOGOFF to continue') -cne 'LOGOFF') {
	Write-Host 'Cancelled; no sessions were signed out.'
	exit 0
}

# Sign out the current session last so this script can process the remaining IDs.
$selectedIds = @($selected | ForEach-Object { $_.Id })
$orderedSessions = @($selectedIds | Where-Object { $_ -ne $currentSessionId })
if ($currentSessionId -in $selectedIds) {
	$orderedSessions += $currentSessionId
}
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
