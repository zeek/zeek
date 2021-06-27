param(
    [Parameter()]
    [ValidateSet("Debug", "Release")]
    [string] $BuildType = "Release"
)

$SourceDirectory = (Convert-Path "$PSScriptRoot/../").Replace("\", "/")
$WorkingDirectory = $pwd.Path

$commands = @()
if (!(Get-Command cl)) {
    $commands += '"C:/Program Files (x86)/Microsoft Visual Studio/2019/Enterprise/VC/Auxiliary/Build/vcvars64.bat"'
}

$commands += @"
cmake.exe
    -G "Ninja"
    -S "$SourceDirectory"
    -B "$WorkingDirectory"
    -DCMAKE_BUILD_TYPE:STRING=$BuildType
    -DCMAKE_INSTALL_PREFIX:PATH="$SourceDirectory/out/install/$BuildType"
    -DDISABLE_PYTHON_BINDINGS=1 `
    2>&1
"@.Replace("`r`n", "")

$commands += @"
cmake.exe --build $WorkingDirectory --config $BuildType
"@

$commands += @"
cmake.exe --install $WorkingDirectory
"@
cmd /c ($commands -join " && ")