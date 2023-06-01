:: See build.cmd for documentation on this call.
call "c:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

cd build

:: This sets up ZEEKPATH and ZEEK_PLUGIN_PATH
call zeek-path-dev.bat

:: Only run the unit tests for now. Btest is supported on Windows but a ton
:: of tests are still failing so it's not worth trying to run it.
src\zeek --test
