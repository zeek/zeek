
include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(pcap)

set(iosource_SRCS
    BPF_Program.cc
    Component.cc
    Manager.cc
    Packet.cc
    PktDumper.cc
    PktSrc.cc
)

bro_add_subdir_library(iosource ${iosource_SRCS})
add_dependencies(bro_iosource generate_outputs)

