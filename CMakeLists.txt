project(Bro)

########################################################################
## CMake Configuration
cmake_minimum_required(VERSION 2.6 FATAL_ERROR)

# Prohibit in-source builds.
if ("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed. Please use "
                        "./configure to choose a build directory and "
                        "initialize the build configuration.")
endif ()

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # uninstall target
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
                    @ONLY)

    add_custom_target(uninstall COMMAND
        ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif ()

########################################################################
## Project/Build Configuration

set(BRO_ROOT_DIR ${CMAKE_INSTALL_PREFIX})
if (NOT POLICYDIR)
    # set the default policy installation path (user did not specify one)
    set(POLICYDIR ${BRO_ROOT_DIR}/share/bro)
endif ()

# sanitize the policy install directory into an absolute path
# (CMake is confused by ~ as a representation of home directory)
get_filename_component(POLICYDIR ${POLICYDIR} ABSOLUTE)

configure_file(bro-path-dev.in ${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev)

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

set(EXTRA_COMPILE_FLAGS "-Wall -Wno-unused")

if (ENABLE_DEBUG)
    set(CMAKE_BUILD_TYPE Debug)
    set(EXTRA_COMPILE_FLAGS "${EXTRA_COMPILE_FLAGS} -DDEBUG")
else ()
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif ()

# Compiler flags may already exist in CMake cache (e.g. when specifying
# CFLAGS environment variable before running cmake for the the first time)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_COMPILE_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_COMPILE_FLAGS}")

########################################################################
## Dependency Configuration

include(FindRequiredPackage)

# Check cache value first to avoid displaying "Found sed" messages everytime
if (NOT SED_EXE)
    find_program(SED_EXE sed)
    if (NOT SED_EXE)
        message(FATAL_ERROR "Could not find required dependency: sed")
    else ()
        message(STATUS "Found sed: ${SED_EXE}")
    endif ()
endif ()

FindRequiredPackage(Perl)
FindRequiredPackage(FLEX)
FindRequiredPackage(BISON)
FindRequiredPackage(PCAP)
FindRequiredPackage(OpenSSL)
FindRequiredPackage(BIND)

if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/aux/binpac/CMakeLists.txt)
    add_subdirectory(aux/binpac)
endif ()
FindRequiredPackage(BinPAC)

if (MISSING_PREREQS)
    foreach (prereq ${MISSING_PREREQ_DESCS})
        message(SEND_ERROR ${prereq})
    endforeach ()
    message(FATAL_ERROR "Configuration aborted due to missing prerequisites")
endif ()

include_directories(BEFORE
                    ${PCAP_INCLUDE_DIR}
                    ${OpenSSL_INCLUDE_DIR}
                    ${BIND_INCLUDE_DIR}
                    ${BinPAC_INCLUDE_DIR}
)

# Optional Dependencies

set(HAVE_LIBMAGIC false)
find_package(LibMagic)
if (LIBMAGIC_FOUND)
    set(HAVE_LIBMAGIC true)
    include_directories(BEFORE ${LibMagic_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibMagic_LIBRARY})
endif ()

set(HAVE_LIBZ false)
find_package(ZLIB)
if (ZLIB_FOUND)
    set(HAVE_LIBZ true)
    include_directories(BEFORE ${ZLIB_INCLUDE_DIR})
    list(APPEND OPTLIBS ${ZLIB_LIBRARY})
endif ()

set(USE_GEOIP false)
find_package(LibGeoIP)
if (LIBGEOIP_FOUND)
    set(USE_GEOIP true)
    include_directories(BEFORE ${LibGeoIP_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibGeoIP_LIBRARY})
endif ()

set(USE_PERFTOOLS false)
if (ENABLE_PERFTOOLS)
    find_package(GooglePerftools)
    if (GOOGLEPERFTOOLS_FOUND)
        set(USE_PERFTOOLS true)
        include_directories(BEFORE ${GooglePerftools_INCLUDE_DIR})
        list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
    endif ()
endif ()

########################################################################
## System Introspection

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)

include(OSSpecific)
include(CheckTypes)
include(CheckHeaders)
include(CheckFunctions)
include(MiscTests)
include(PCAPTests)
include(OpenSSLTests)
include(CheckNameserCompat)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

########################################################################
## Recurse on sub-directories

add_subdirectory(src)
add_subdirectory(policy)
#add_subdirectory(scripts)
#add_subdirectory(doc)

include(CheckOptionalBuildSources)

CheckOptionalBuildSources(aux/broctl   Broctl   INSTALL_BROCTL)
CheckOptionalBuildSources(aux/bro-aux  Bro-Aux  INSTALL_AUX_TOOLS)
CheckOptionalBuildSources(aux/broccoli Broccoli INSTALL_BROCCOLI)

########################################################################
## Packaging Setup

# If this CMake project is a sub-project of another, we will not
# configure the generic packaging because CPack will fail in the case
# that the parent project has already configured packaging
if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()

########################################################################
## Build Summary

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

if (INSTALL_BROCTL)
    if (STANDALONE)
        set(BROCTL_INSTALL_MODE "standalone")
    else ()
        set(BROCTL_INSTALL_MODE "cluster")
    endif ()
else ()
    set(BROCTL_INSTALL_MODE "false")
endif ()

message(
    "\n====================|  Bro Build Summary  |====================="
    "\n"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nPolicy dir:        ${POLICYDIR}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nBroccoli:          ${INSTALL_BROCCOLI}"
    "\nBroctl:            ${BROCTL_INSTALL_MODE}"
    "\nAux. Tools:        ${INSTALL_AUX_TOOLS}"
    "\n"
    "\nGeoIP:             ${USE_GEOIP}"
    "\nlibz:              ${HAVE_LIBZ}"
    "\nlibmagic:          ${HAVE_LIBMAGIC}"
    "\nGoogle perftools:  ${USE_PERFTOOLS}"
    "\n"
    "\n================================================================\n"
)

########################################################################
## Show warning when installing user is different from the one that configured

install(CODE "
    if (NOT $ENV{USER} STREQUAL \$ENV{USER})
        message(STATUS \"ATTENTION: Install is being performed by user \"
                \"'\$ENV{USER}', but the build directory was configured by \"
                \"user '$ENV{USER}'. This may result in a permissions error \"
                \"when writing the install manifest, but you can ignore it \"
                \"and consider the installation as successful if you don't \"
                \"care about the install manifest.\")
    endif ()
")
