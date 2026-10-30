# Read-only export. Run PowerShell on the Windows host with access to the logs.
param(
    [string]$OutputPath = ".\events.jsonl",
    [int]$MaxEvents = 1000
)
$ErrorActionPreference = "Stop"
if ($MaxEvents -lt 1 -or $MaxEvents -gt 100000) {
    throw "MaxEvents must be between 1 and 100000"
}
$rows = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1, 3, 10
} -MaxEvents $MaxEvents | ForEach-Object {
    [xml]$xml = $_.ToXml()
    $data = @{}
    foreach ($item in $xml.Event.EventData.Data) {
        $data[[string]$item.Name] = [string]$item.'#text'
    }
    @{
        record_id = [string]$_.RecordId
        event_id = [int]$_.Id
        host = [string]$_.MachineName
        timestamp = $_.TimeCreated.ToUniversalTime().ToString('o')
        data = $data
    } | ConvertTo-Json -Compress -Depth 8
}
# UTF-8 without BOM, compatible with PowerShell 5.1 and 7.
[System.IO.File]::WriteAllLines(
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath),
    [string[]]$rows,
    (New-Object System.Text.UTF8Encoding($false))
)
