param(
	[int]$LookbackHours = 24,
	[int]$PollSeconds = 5,
	[switch]$Once,
	[string]$OutputPath = (Join-Path $PSScriptRoot 'ip-connections.csv')
)

# Run elevated for Security and Windows Firewall events. Firewall connection
# auditing (Security events 5156/5157) must be enabled to record arbitrary ports.
$ErrorActionPreference = 'SilentlyContinue'
$seen = @{}
$knownServices = @{ 22 = 'SSH'; 3389 = 'RDP' }

function Get-EventFields($Event) {
	$fields = @{}
	$xml = [xml]$Event.ToXml()
	foreach ($item in $xml.Event.EventData.Data) {
		$fields[$item.GetAttribute('Name')] = $item.InnerText
	}
	return $fields
}

function Add-ConnectionLog($Key, $Time, $RemoteIP, $RemotePort, $LocalPort, $Service, $Source) {
	if ([string]::IsNullOrWhiteSpace($RemoteIP) -or $RemoteIP -in @('-', '::', '0.0.0.0', '127.0.0.1', '::1')) { return }
	if ($seen.ContainsKey($Key)) { return }
	$seen[$Key] = $true

	if ($Service -eq 'Unknown' -and $LocalPort -match '^\d+$' -and $knownServices.ContainsKey([int]$LocalPort)) {
		$Service = $knownServices[[int]$LocalPort]
	}
	[pscustomobject]@{
		Time = $Time
		RemoteIP = $RemoteIP
		RemotePort = $RemotePort
		LocalPort = $LocalPort
		Service = $Service
		Source = $Source
	} | Export-Csv -Path $OutputPath -NoTypeInformation -Append
	Write-Host ("{0:u} {1} -> local port {2} ({3}) [{4}]" -f $Time, $RemoteIP, $LocalPort, $Service, $Source)
}

function Read-ConnectionEvents($Since) {
	$sources = @(
		@{ Log = 'Security'; Ids = @(5156, 5157, 4624) },
		@{ Log = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'; Ids = @(1149) },
		@{ Log = 'OpenSSH/Operational'; Ids = @(4, 5) }
	)

	foreach ($source in $sources) {
		$events = Get-WinEvent -FilterHashtable @{ LogName = $source.Log; Id = $source.Ids; StartTime = $Since } -ErrorAction SilentlyContinue
		foreach ($event in $events) {
			$key = "$($source.Log):$($event.RecordId)"
			if ($seen.ContainsKey($key)) { continue }
			$f = Get-EventFields $event
			$remote = ''; $remotePort = ''; $localPort = ''; $service = 'Unknown'

			if ($event.Id -in @(5156, 5157)) {
				if ($f.Direction -notin @('%%14592', 'Inbound', '1')) { continue }
				$remote = $f.SourceAddress; $remotePort = $f.SourcePort; $localPort = $f.DestPort
			} elseif ($event.Id -eq 1149) {
				$remote = $f.Param3
				if (-not $remote) { $remote = [regex]::Match($event.Message, '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])').Value }
				$localPort = '3389'; $service = 'RDP'
			} elseif ($event.Id -eq 4624) {
				if ($f.LogonType -notin @('3', '10')) { continue }
				$remote = $f.IpAddress; $remotePort = $f.IpPort
				if ($f.LogonType -eq '10') { $localPort = '3389'; $service = 'RDP' }
			} else {
				$remote = [regex]::Match($event.Message, '(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])').Value
				if (-not $remote) { $remote = [regex]::Match($event.Message, '(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:]{2,}(?![\w:])').Value }
				if ($remote) { $localPort = '22'; $service = 'SSH' }
			}

			Add-ConnectionLog $key $event.TimeCreated $remote $remotePort $localPort $service $source.Log
		}
	}
}

if (-not (Test-Path $OutputPath)) {
	'Time,RemoteIP,RemotePort,LocalPort,Service,Source' | Set-Content -Path $OutputPath
}

# Record connections already established when the script starts.
foreach ($connection in (Get-NetTCPConnection -State Established)) {
	$service = 'Unknown'
	if ($knownServices.ContainsKey([int]$connection.LocalPort)) { $service = $knownServices[[int]$connection.LocalPort] }
	$key = "active:$($connection.LocalAddress):$($connection.LocalPort):$($connection.RemoteAddress):$($connection.RemotePort)"
	Add-ConnectionLog $key (Get-Date) $connection.RemoteAddress $connection.RemotePort $connection.LocalPort $service 'Active TCP connection'
}

Read-ConnectionEvents (Get-Date).AddHours(-$LookbackHours)
if (-not $Once) {
	while ($true) {
		Start-Sleep -Seconds ([Math]::Max(1, $PollSeconds))
		Read-ConnectionEvents (Get-Date).AddMinutes(-2)
	}
}
