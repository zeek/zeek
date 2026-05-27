@echo on

echo %ZEEK_CI_CPUS%
powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-CimInstance Win32_Processor | Select-Object NumberOfCores, NumberOfLogicalProcessors | Format-List"
systeminfo
dir C:
choco list

:: Make sure that long paths are enabled. Otherwise ccache will probably complain about it.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
