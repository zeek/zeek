param (
    [string] $Architecture='x64'
)

if (!(Get-Module VSSetup)) 
{
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module VSSetup -Force
}

function Get-VSInstallPath {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [int] $MaxVersion
    )
    $latest = Get-VSSetupInstance `
                | where { $_.InstallationVersion.Major -le $MaxVersion } `
                | Select-VSSetupInstance -Require Microsoft.VisualStudio.VC.CMake -Latest

    if (!$latest)
    {
        throw [System.IO.FileNotFoundException]::new("No Visual Studio installation found that matches max version: $MaxVersion!")
    }
    return $latest.InstallationPath
}

function Where-Program {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string] $Program
    )
    process
    {
        return Get-Command $Program | select Source -ExpandProperty source | Split-Path -Parent
    }
}

function Persist-EnvironmentVariable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [string] $Name
    )
    process
    {
        $value=[System.Environment]::GetEnvironmentVariable($Name)
        [System.Environment]::SetEnvironmentVariable($Name, $value, [System.EnvironmentVariableTarget]::Machine)
    }
}

$VsInstallationPath = Get-VSInstallPath -MaxVersion 16
Write-Host "Found VS installation: $VsInstallationPath"

[array] $originalEnv = [System.Environment]::GetEnvironmentVariables().Keys

Import-Module "$VsInstallationPath\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $VsInstallationPath -SkipAutomaticLocation -DevCmdArguments "-arch=$Architecture"

$Programs = 'cmake', 'Ninja', 'cl'
$programsPath = $Programs | Where-Program
Write-Host "Found paths for $($Programs -join ', '): $($programsPath -join ', ')"

$newPath = "$($programsPath -join ';');${env:Path}"
Write-Host "Persisting new PATH: $newPath"
[System.Environment]::SetEnvironmentVariable('PATH', $newPath, [System.EnvironmentVariableTarget]::Machine)

[array] $vsEnv = [System.Environment]::GetEnvironmentVariables().Keys
[array] $newEnv = $vsEnv | where { $_ -notin $originalEnv -and $_ -ne 'PATH' }

Write-Host "Persisting new environment variables: $($newEnv -join ', ')"
$newEnv | Persist-EnvironmentVariable
