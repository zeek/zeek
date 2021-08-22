[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

choco install conan -y
choco install sed -y
choco install winflexbison -y
if (!(Get-Command python))
{
    choco install python -y
}

[System.Environment]::SetEnvironmentVariable('PATH', "C:\Program Files\Git\bin;${env:PATH}", [System.EnvironmentVariableTarget]::Machine)