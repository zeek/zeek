:: See build.cmd for documentation on this call.
call "c:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

:: We currently don't have any tests to run on Windows, so this is just commented out.
:: We'll expand on this later.
:: cd build
:: ctest -C release || exit \b 1
