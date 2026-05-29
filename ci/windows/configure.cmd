:: Import the visual studio compiler environment into the one running in the
:: cmd current shell. This path is hard coded to the one on the CI image, but
:: can be adjusted if running builds locally. Unfortunately, the initial path
:: isn't in the environment so we have to hardcode the whole path.
call "%VSINSTALLDIR%VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

:: vcvarsall always sets this to a value, so we need to reset it so that the
:: remainder of the commands can set it if needed.
set ERRORLEVEL=

mkdir build
cd build

cmake.exe .. -DCMAKE_BUILD_TYPE=release -DVCPKG_TARGET_TRIPLET="x64-windows-static" -DENABLE_ZEEK_UNIT_TESTS=yes -DENABLE_CCACHE=yes -G Ninja
if %ERRORLEVEL% neq 0 exit %ERRORLEVEL%
