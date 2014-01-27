
include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(pktsrc)

set(iosource_SRCS
    Component.cc
    Manager.cc

    pktsrc/Component.cc
    pktsrc/PktDumper.cc
    pktsrc/PktSrc.cc
)

bro_add_subdir_library(iosource ${iosource_SRCS})
add_dependencies(bro_iosource generate_outputs)

