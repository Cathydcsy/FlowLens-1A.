param([Parameter(Mandatory=$true)][string]$Stage, [switch]$Gui, [string]$PythonPath = 'python')
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$stageDirectory = Join-Path $projectRoot "output\plus\$Stage"
New-Item -ItemType Directory -Path $stageDirectory -Force | Out-Null
if ($PythonPath -eq 'python') {
    $resolved = (Get-Command python -ErrorAction SilentlyContinue).Source
    if ($resolved) { $PythonPath = $resolved }
}
$pythonPath = $PythonPath
$results = @{}
foreach ($configuration in @('Release','Debug')) {
    $buildDirectory = if ($configuration -eq 'Release') { 'build-plus-release' } else { 'build-plus-debug' }
    $buildArguments = @{ BuildDirectory=$buildDirectory; CoreOnly=$true }
    if ($Gui -and $configuration -eq 'Release') { $buildArguments.CoreOnly=$false }
    if ($configuration -eq 'Debug') { $buildArguments.Checked=$true }
    & "$PSScriptRoot\build.ps1" @buildArguments *> (Join-Path $stageDirectory "$configuration-build.txt")
    if ($LASTEXITCODE) { throw "$configuration build failed; inspect $stageDirectory" }
    $coreOutput = & (Join-Path $projectRoot "$buildDirectory\flowlens_tests.exe") (Join-Path $projectRoot 'samples')
    if ($LASTEXITCODE) { throw "$configuration original tests failed" }
    $coreOutput | Set-Content -LiteralPath (Join-Path $stageDirectory "$configuration-core.txt") -Encoding utf8
    $expected = if ($configuration -eq 'Release') { 52 } else { 53 }
    if (($coreOutput -join "
") -notmatch "RESULT $expected checks passed") { throw 'Original test count changed unexpectedly' }
    $plusOutput = & (Join-Path $projectRoot "$buildDirectory\flowlens_plus_tests.exe") (Join-Path $projectRoot 'samples')
    if ($LASTEXITCODE) { throw "$configuration additional tests failed" }
    $plusOutput | Set-Content -LiteralPath (Join-Path $stageDirectory "$configuration-plus.txt") -Encoding utf8
    $results[$configuration] = @{ original=$expected; additional=($plusOutput | Select-Object -Last 1); status='PASS' }
    $attributionOutput = & (Join-Path $projectRoot "$buildDirectory\flowlens_attribution_tests.exe") (Join-Path $projectRoot 'samples')
    if ($LASTEXITCODE) { throw "$configuration process association tests failed" }
    $attributionOutput | Set-Content -LiteralPath (Join-Path $stageDirectory "$configuration-attribution.txt") -Encoding utf8
    if (($attributionOutput -join "
") -notmatch 'RESULT 22 attribution checks passed') { throw 'Process association test count changed unexpectedly' }
    $results[$configuration].attribution = 22
    Write-Output "$configuration original $expected and additional tests passed."
}
& $pythonPath -c "import scapy, psutil" 2>$null
if ($LASTEXITCODE) { throw "Python $pythonPath is missing scapy or psutil. Run: $pythonPath -m pip install scapy psutil" }
& $pythonPath "$PSScriptRoot\verify.py" --exe (Join-Path $projectRoot 'build-plus-release\flowlens_cli.exe') --output (Join-Path $stageDirectory 'scapy') *> (Join-Path $stageDirectory 'scapy.txt')
if ($LASTEXITCODE) { throw 'Scapy validation failed' }
$scapy = Get-Content -LiteralPath (Join-Path $stageDirectory 'scapy\verification.json') -Raw | ConvertFrom-Json
if ($scapy.passed -ne 117 -or $scapy.failed -ne 0) { throw 'Scapy 117-check baseline regressed' }
$results.Scapy = @{ original=117; status='PASS' }
if (Test-Path -LiteralPath (Join-Path $projectRoot 'samples\plus\expected.json')) {
    & $pythonPath "$PSScriptRoot\verify_protocols.py" --exe (Join-Path $projectRoot 'build-plus-release\flowlens_cli.exe') --output (Join-Path $stageDirectory 'protocols') *> (Join-Path $stageDirectory 'protocols.txt')
    if ($LASTEXITCODE) { throw 'Additional independent protocol validation failed' }
    $results.Protocols = @{ status='PASS' }
}
if ($Gui) {
    & $pythonPath "$PSScriptRoot\verify_ui.py" --output (Join-Path $stageDirectory 'gui') *> (Join-Path $stageDirectory 'gui.txt')
    if ($LASTEXITCODE) { throw 'Offscreen Qt UI validation failed' }
    $results.GUI = @{ status='PASS'; method='Qt hidden widget rendering; no desktop capture' }
}
$results | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $stageDirectory 'validation.json') -Encoding utf8
Write-Output "PASS $Stage : Release 52 / Debug 53 / Scapy 117"
