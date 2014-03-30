project(Bro C CXX)
cmake_minimum_required(VERSION 2.6.3 FATAL_ERROR)
include(cmake/CommonCMakeConfig.cmake)

########################################################################
## Project/Build Configuration

set(BRO_ROOT_DIR ${CMAKE_INSTALL_PREFIX})
if (NOT BRO_SCRIPT_INSTALL_PATH)
    # set the default Bro script installation path (user did not specify one)
    set(BRO_SCRIPT_INSTALL_PATH ${BRO_ROOT_DIR}/share/bro)
endif ()

# sanitize the Bro script install directory into an absolute path
# (CMake is confused by ~ as a representation of home directory)
get_filename_component(BRO_SCRIPT_INSTALL_PATH ${BRO_SCRIPT_INSTALL_PATH}
    ABSOLUTE)

configure_file(bro-path-dev.in ${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev)
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev.sh
     "export BROPATH=`${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev`\n"
     "export PATH=\"${CMAKE_CURRENT_BINARY_DIR}/src\":$PATH\n")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev.csh
     "setenv BROPATH `${CMAKE_CURRENT_BINARY_DIR}/bro-path-dev`\n"
     "setenv PATH \"${CMAKE_CURRENT_BINARY_DIR}/src\":$PATH\n")

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)
string(REPLACE "." " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
set(VERSION_MAJ_MIN "${VERSION_MAJOR}.${VERSION_MINOR}")

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
FindRequiredPackage(ZLIB)

if (NOT BinPAC_ROOT_DIR AND
    EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/aux/binpac/CMakeLists.txt)
    add_subdirectory(aux/binpac)
endif ()
FindRequiredPackage(BinPAC)

if (ENABLE_JEMALLOC)
    find_package(JeMalloc)
endif ()

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
                    ${ZLIB_INCLUDE_DIR}
                    ${JEMALLOC_INCLUDE_DIR}
)

# Optional Dependencies

set(USE_GEOIP false)
find_package(LibGeoIP)
if (LIBGEOIP_FOUND)
    set(USE_GEOIP true)
    include_directories(BEFORE ${LibGeoIP_INCLUDE_DIR})
    list(APPEND OPTLIBS ${LibGeoIP_LIBRARY})
endif ()

set(HAVE_PERFTOOLS false)
set(USE_PERFTOOLS_DEBUG false)
set(USE_PERFTOOLS_TCMALLOC false)

if (NOT DISABLE_PERFTOOLS)
   find_package(GooglePerftools)
endif ()

if (GOOGLEPERFTOOLS_FOUND)
    set(HAVE_PERFTOOLS true)
    # Non-Linux systems may not be well-supported by gperftools, so
    # require explicit request from user to enable it in that case.
    if (${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ENABLE_PERFTOOLS)
        set(USE_PERFTOOLS_TCMALLOC true)

        if (ENABLE_PERFTOOLS_DEBUG)
            # Enable heap debugging with perftools.
            set(USE_PERFTOOLS_DEBUG true)
            include_directories(BEFORE ${GooglePerftools_INCLUDE_DIR})
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES_DEBUG})
        else ()
            # Link in tcmalloc for better performance.
            list(APPEND OPTLIBS ${GooglePerftools_LIBRARIES})
        endif ()
    endif ()
endif ()

set(USE_DATASERIES false)
find_package(Lintel)
find_package(DataSeries)
find_package(LibXML2)

if (NOT DISABLE_DATASERIES AND
    LINTEL_FOUND AND DATASERIES_FOUND AND LIBXML2_FOUND)
    set(USE_DATASERIES true)
	include_directories(BEFORE ${Lintel_INCLUDE_DIR})
	include_directories(BEFORE ${DataSeries_INCLUDE_DIR})
	include_directories(BEFORE ${LibXML2_INCLUDE_DIR})
	list(APPEND OPTLIBS ${Lintel_LIBRARIES})
	list(APPEND OPTLIBS ${DataSeries_LIBRARIES})
	list(APPEND OPTLIBS ${LibXML2_LIBRARIES})
endif()

set(USE_ELASTICSEARCH false)
set(USE_CURL false)
find_package(LibCURL)

if (NOT DISABLE_ELASTICSEARCH AND LIBCURL_FOUND)
  set(USE_ELASTICSEARCH true)
  set(USE_CURL true)
  include_directories(BEFORE ${LibCURL_INCLUDE_DIR})
  list(APPEND OPTLIBS ${LibCURL_LIBRARIES})
endif()

if (ENABLE_PERFTOOLS_DEBUG OR ENABLE_PERFTOOLS)
    # Just a no op to prevent CMake from complaining about manually-specified
    # ENABLE_PERFTOOLS_DEBUG or ENABLE_PERFTOOLS not being used if google
    # perftools weren't found
endif ()

set(brodeps
    ${BinPAC_LIBRARY}
    ${PCAP_LIBRARY}
    ${OpenSSL_LIBRARIES}
    ${BIND_LIBRARY}
    ${ZLIB_LIBRARY}
    ${JEMALLOC_LIBRARIES}
    ${OPTLIBS}
)

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
add_subdirectory(scripts)
add_subdirectory(doc)

include(CheckOptionalBuildSources)

CheckOptionalBuildSources(aux/broctl   Broctl   INSTALL_BROCTL)
CheckOptionalBuildSources(aux/bro-aux  Bro-Aux  INSTALL_AUX_TOOLS)
CheckOptionalBuildSources(aux/broccoli Broccoli INSTALL_BROCCOLI)

########################################################################
## Packaging Setup

if (INSTALL_BROCTL)
    # CPack RPM Generator may not automatically detect this
    set(CPACK_RPM_PACKAGE_REQUIRES "python >= 2.6.0")
endif ()

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

message(
    "\n====================|  Bro Build Summary  |====================="
    "\n"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nBro Script Path:   ${BRO_SCRIPT_INSTALL_PATH}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\nBroccoli:          ${INSTALL_BROCCOLI}"
    "\nBroctl:            ${INSTALL_BROCTL}"
    "\nAux. Tools:        ${INSTALL_AUX_TOOLS}"
    "\n"
    "\nGeoIP:             ${USE_GEOIP}"
    "\ngperftools found:  ${HAVE_PERFTOOLS}"
    "\n        tcmalloc:  ${USE_PERFTOOLS_TCMALLOC}"
    "\n       debugging:  ${USE_PERFTOOLS_DEBUG}"
    "\njemalloc:          ${ENABLE_JEMALLOC}"
    "\ncURL:              ${USE_CURL}"
    "\n"
    "\nDataSeries:        ${USE_DATASERIES}"
    "\nElasticSearch:     ${USE_ELASTICSEARCH}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
