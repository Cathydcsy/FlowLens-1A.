param([string]$CaptureFile = '')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$program = Join-Path $projectRoot 'dist\FlowLens\flowlens_cli.exe'
if (!$CaptureFile) { $CaptureFile = Join-Path $projectRoot 'samples\showcase.pcap' }
$rules = 'tcp','udp','ipv4','ipv6','icmp','icmpv6','dns','tcp and port == 18080'
$rows = foreach ($rule in $rules) {
    $raw = & $program $CaptureFile --filter $rule
    if ($LASTEXITCODE) { throw "Filter failed: $rule" }
    $result = $raw | ConvertFrom-Json
    [PSCustomObject]@{
        Filter = $rule
        Matched = $result.matched
        Total = $result.packets
    }
}
$rows | Format-Table Filter,Matched,Total -AutoSize
