# Custom triplet for MSVC compiler version 17

set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_CXX_FLAGS "${VCPKG_CXX_FLAGS} /guard:cf /Z7")
set(VCPKG_C_FLAGS "${VCPKG_C_FLAGS} /guard:cf /Z7")
set(VCPKG_LINKER_FLAGS "${VCPKG_LINKER_FLAGS} /debug:full")

set(VCPKG_DISABLE_COMPILER_TRACKING true)
