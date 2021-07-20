param(
    [Parameter()]
    [ValidateSet("Debug", "Release")]
    [string] $BuildType = "Release"
)

$SourceDirectory = (Convert-Path "$PSScriptRoot/../").Replace("\", "/")
$WorkingDirectory = "$pwd"
$BuildOutputDirectory = "$SourceDirectory/out/build/x64/$BuildType"
$InstallDirectory = "$SourceDirectory/out/install/x64/$BuildType"

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
    -DCMAKE_INSTALL_PREFIX:PATH="$InstallDirectory"
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

Write-Host "Copying build output to $BuildOutputDirectory..."
mkdir $BuildOutputDirectory -Force | Out-Null
Get-ChildItem $WorkingDirectory -Recurse -Attributes !ReparsePoint | foreach { 
    $path = $_.FullName.Replace("$pwd", $BuildOutputDirectory)
    $parent = Split-Path -Parent $path
    mkdir $parent -Force | Out-Null
    Copy-Item $_.FullName -Destination $path -Force
}
Write-Host "Done."