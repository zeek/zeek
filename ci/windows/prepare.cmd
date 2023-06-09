@echo on

echo %ZEEK_CI_CPUS%
wmic cpu get NumberOfCores, NumberOfLogicalProcessors/Format:List
systeminfo
dir C:
choco list
