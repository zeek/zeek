:: Import the visual studio compiler environment into the one running in the
:: cmd current shell. This path is hard coded to the one on the CI image, but
:: can be adjusted if running builds locally. Unfortunately, the initial path
:: isn't in the environment so we have to hardcode the whole path.
call "c:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

if %ERRORLEVEL% neq 0 exit %ERRORLEVEL%

:: vcvarsall always sets this to a value, so we need to reset it so that the
:: remainder of the commands can set it if needed.
set ERRORLEVEL=

:: Make sure that long paths are enabled. Otherwise ccache will probably complain about it.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
reg query "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled

:: configure.cmd uses a Ninja generator, so this should use the maximum number of CPUs
:: without -j
cmake.exe --build build
if %ERRORLEVEL% neq 0 exit %ERRORLEVEL%
