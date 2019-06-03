# See the file "COPYING" in the main distribution directory for copyright.

include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(zeekygen_SRCS
    Manager.cc
    Info.h
    PackageInfo.cc
    ScriptInfo.cc
    IdentifierInfo.cc
    Target.cc
    Configuration.cc
    ReStructuredTextTable.cc
    utils.cc
)

bif_target(zeekygen.bif)
bro_add_subdir_library(zeekygen ${zeekygen_SRCS})

add_dependencies(bro_zeekygen generate_outputs)
