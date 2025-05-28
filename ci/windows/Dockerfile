# escape=`
FROM mcr.microsoft.com/dotnet/framework/sdk:4.8-windowsservercore-ltsc2019

SHELL [ "powershell" ]

# A version field to invalidatea Cirrus's build cache when needed, as suggested in
# https://github.com/cirruslabs/cirrus-ci-docs/issues/544#issuecomment-566066822
ENV DOCKERFILE_VERSION 20250528

RUN Set-ExecutionPolicy Unrestricted -Force

# Install Chocolatey
RUN [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; `
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install prerequisites
RUN choco install -y --no-progress visualstudio2022buildtools --version=117.14.1
RUN choco install -y --no-progress visualstudio2022-workload-vctools --version=1.0.0 --package-parameters '--add Microsoft.VisualStudio.Component.VC.ATLMFC'
RUN choco install -y --no-progress sed
RUN choco install -y --no-progress winflexbison3
RUN choco install -y --no-progress msysgit
RUN choco install -y --no-progress python
RUN choco install -y --no-progress openssl --version=3.1.1

# Set working environment.
SHELL [ "cmd", "/c" ]
RUN setx /M PATH "%PATH%;C:\\Program Files\\Git\\bin"
RUN setx /M CONAN_SKIP_BROKEN_SYMLINKS_CHECK 1
RUN mkdir C:\build
WORKDIR C:\build

# This entry point starts the developer command prompt and launches the PowerShell shell.
ENTRYPOINT ["C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\Common7\\Tools\\VsDevCmd.bat", "-arch=x64", "&&", "powershell.exe", "-NoLogo", "-ExecutionPolicy", "Unrestricted"]
