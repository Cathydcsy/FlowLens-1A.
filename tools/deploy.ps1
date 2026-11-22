param([string]$QtRoot='D:\ProgramData\Anaconda3\Library')
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$appRoot=Join-Path $projectRoot 'dist\FlowLens'
New-Item -ItemType Directory -Path $appRoot -Force | Out-Null
foreach($name in @('FlowLens.exe','flowlens_cli.exe','flowlens_tests.exe','flowlens_plus_tests.exe','flowlens_attribution_tests.exe','flowlens_native_probe.exe')) { Copy-Item -LiteralPath (Join-Path $projectRoot "build-native\$name") -Destination $appRoot -Force }
& (Join-Path $QtRoot 'bin\windeployqt.exe') --release --no-compiler-runtime --no-translations --no-system-d3d-compiler --no-opengl-sw --dir $appRoot (Join-Path $appRoot 'FlowLens.exe')
if($LASTEXITCODE){throw 'Qt deployment failed'}
foreach($name in @('zlib.dll','libpng16.dll','icuin58.dll','icuuc58.dll','icudt58.dll')) {
    $dependency=Join-Path $QtRoot "bin\$name"
    if(Test-Path -LiteralPath $dependency){Copy-Item -LiteralPath $dependency -Destination $appRoot -Force}
}
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsRoot=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$crtRoot=Get-ChildItem -LiteralPath (Join-Path $vsRoot 'VC\Redist\MSVC') -Directory | Where-Object {$_.Name -match '^\d'} | Sort-Object Name -Descending | Select-Object -First 1
if($crtRoot){$crt=Join-Path $crtRoot.FullName 'x64\Microsoft.VC142.CRT';if(Test-Path -LiteralPath $crt){Get-ChildItem -LiteralPath $crt -Filter '*.dll' | Copy-Item -Destination $appRoot -Force}}
Copy-Item -LiteralPath (Join-Path $projectRoot 'samples') -Destination $appRoot -Recurse -Force
Set-Content -LiteralPath (Join-Path $appRoot 'qt.conf') -Value "[Paths]`nPlugins=." -Encoding ascii
Write-Output "Portable application: $appRoot"
