cmake_minimum_required(VERSION 3.5 FATAL_ERROR)
project(Gen-ZAM C CXX)

include(cmake/CommonCMakeConfig.cmake)

include(RequireCXX17)

set(GEN_ZAM_SRCS src/Gen-ZAM.cc)
set(GEN_ZAM_HEADERS src/Gen-ZAM.h)
add_executable(gen-zam ${GEN_ZAM_SRCS} ${GEN_ZAM_HEADERS})
install(TARGETS gen-zam DESTINATION bin)

if (CMAKE_BUILD_TYPE)
    string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)
endif ()

message(
    "\n===================|  Gen-ZAM Build Summary  |==================\n"
    "\n"
    "\nBuild type:        ${CMAKE_BUILD_TYPE}"
    "\nBuild dir:         ${PROJECT_BINARY_DIR}"
    "\nInstall prefix:    ${CMAKE_INSTALL_PREFIX}"
    "\nDebug mode:        ${ENABLE_DEBUG}"
    "\n"
    "\nCC:                ${CMAKE_C_COMPILER}"
    "\nCFLAGS:            ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:               ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:          ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\nCPP:               ${CMAKE_CXX_COMPILER}"
    "\n"
    "\n================================================================\n"
)

include(UserChangedWarning)
