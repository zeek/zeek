:: See build.cmd for documentation on this call.
call "c:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

:: Install btest's Windows dependency.
pip install multiprocess

cd build

:: This sets up ZEEKPATH and ZEEK_PLUGIN_PATH
call zeek-path-dev.bat

:: Run unit tests.
src\zeek --test
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

:: Run btests via git bash.
cd ..\testing\btest
"C:\Program Files\Git\bin\bash.exe" ..\..\ci\windows\run-btests.sh
