param([string]$QtRoot = 'D:\ProgramData\Anaconda3\Library', [switch]$CoreOnly, [switch]$Sanitize, [switch]$Checked, [string]$BuildDirectory = '')
$ErrorActionPreference='Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$vswherePath = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path -LiteralPath $vswherePath)) { throw 'Install Visual Studio with Desktop development with C++.' }
$vsRoot = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vsRoot) { throw 'Visual C++ build tools were not found.' }
$cmakePath = Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$cmakeCommand = Get-Command cmake -ErrorAction SilentlyContinue
if ($cmakeCommand) { $cmakePath=$cmakeCommand.Source }
$buildRoot=Join-Path $projectRoot $(if($Sanitize){'build-asan'}elseif($Checked){'build-checked'}else{'build-native'})
if ($BuildDirectory) { $buildRoot = Join-Path $projectRoot $BuildDirectory }
$vcToolsRoot=(Get-ChildItem -LiteralPath (Join-Path $vsRoot 'VC\Tools\MSVC') -Directory | Sort-Object Name -Descending | Select-Object -First 1).FullName
$sdkRoots=@('D:\Windows Kits\10',"${env:ProgramFiles(x86)}\Windows Kits\10")
$sdkRoot=$sdkRoots | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'Include') } | Select-Object -First 1
if(!$sdkRoot){throw 'Windows SDK was not found.'}
$sdkVersion=(Get-ChildItem -LiteralPath (Join-Path $sdkRoot 'Include') -Directory | Sort-Object Name -Descending | Select-Object -First 1).Name
$compilerDir=Join-Path $vcToolsRoot 'bin\Hostx64\x64'
$sdkBin=Join-Path $sdkRoot "bin\$sdkVersion\x64"
$ninjaDir=Join-Path $vsRoot 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja'
$env:PATH="$compilerDir;$sdkBin;$ninjaDir;$(Join-Path $QtRoot 'bin');$env:PATH"
$env:INCLUDE="$(Join-Path $vcToolsRoot 'include');$(Join-Path $sdkRoot "Include\$sdkVersion\ucrt");$(Join-Path $sdkRoot "Include\$sdkVersion\shared");$(Join-Path $sdkRoot "Include\$sdkVersion\um")"
$env:LIB="$(Join-Path $vcToolsRoot 'lib\x64');$(Join-Path $sdkRoot "Lib\$sdkVersion\ucrt\x64");$(Join-Path $sdkRoot "Lib\$sdkVersion\um\x64")"
$env:VSLANG='1033'
$guiValue=if($CoreOnly){'OFF'}else{'ON'}
$sanitizerValue=if($Sanitize){'ON'}else{'OFF'}
$configuration=if($Checked){'Debug'}else{'Release'}
$compilerCmake=(Join-Path $compilerDir 'cl.exe').Replace('\','/')
$rcCmake=(Join-Path $sdkBin 'rc.exe').Replace('\','/')
$mtCmake=(Join-Path $sdkBin 'mt.exe').Replace('\','/')
& $cmakePath -S $projectRoot -B $buildRoot -G Ninja "-DCMAKE_BUILD_TYPE=$configuration" "-DCMAKE_CXX_COMPILER=$compilerCmake" "-DCMAKE_RC_COMPILER=$rcCmake" "-DCMAKE_MT=$mtCmake" "-DCMAKE_PREFIX_PATH=$($QtRoot.Replace('\','/'))" "-DFLOWLENS_BUILD_GUI=$guiValue" "-DFLOWLENS_SANITIZE=$sanitizerValue"
if($LASTEXITCODE){throw 'Configuration failed'}
# 本机 MSVC 的诊断信息是中文，先清理再构建可以避免
# 旧版 CMake/Ninja 识别不了这些诊断时留下过期对象文件，导致 ABI 不一致。
& $cmakePath --build $buildRoot --config $configuration --parallel 4 --clean-first
if($LASTEXITCODE){throw 'Build failed'}
if($Sanitize){Copy-Item -LiteralPath (Join-Path $compilerDir 'clang_rt.asan_dynamic-x86_64.dll') -Destination $buildRoot -Force}
if($Checked){
    $debugCrt=Join-Path $vsRoot 'VC\Redist\MSVC\14.29.30133\debug_nonredist\x64\Microsoft.VC142.DebugCRT'
    if(Test-Path -LiteralPath $debugCrt){Get-ChildItem -LiteralPath $debugCrt -Filter '*.dll' | Copy-Item -Destination $buildRoot -Force}
}
& (Join-Path $buildRoot 'flowlens_tests.exe') (Join-Path $projectRoot 'samples')
if($LASTEXITCODE){throw 'Core tests failed'}
Write-Output 'Build and core tests passed.'
