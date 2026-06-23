:: See build.cmd for documentation on this call.
call "%VSINSTALLDIR%VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

:: vcvarsall always sets this to a value, so we need to reset it so that the
:: remainder of the commands can set it if needed.
set ERRORLEVEL=

:: Install btest's Windows dependency.
pip install multiprocess

cd build

:: This sets up ZEEKPATH and ZEEK_PLUGIN_PATH
call zeek-path-dev.bat

:: Run unit tests.
src\zeek --test
if %ERRORLEVEL% neq 0 exit %ERRORLEVEL%

rem :: Run btests via git bash.
rem cd ..\testing\btest
rem "C:\Program Files\Git\bin\bash.exe" ..\..\ci\windows\run-btests.sh
rem if %ERRORLEVEL% neq 0 exit %ERRORLEVEL%
