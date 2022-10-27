:: Import the visual studio compiler environment into the one running in the
:: cmd current shell. This path is hard coded to the one on the CI image, but
:: can be adjusted if running builds locally. Unfortunately, the initial path
:: isn't in the environment so we have to hardcode the whole path.
call "c:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64

mkdir build
cd build

cmake.exe .. -DCMAKE_BUILD_TYPE=release -DENABLE_ZEEK_UNIT_TESTS=yes -G Ninja
cmake.exe --build .
