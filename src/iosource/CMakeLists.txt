zeek_add_subdir_library(
    iosource
    INCLUDE_DIRS
    ${LIBKQUEUE_INCLUDE_DIRS}
    DEPENDENCIES
    ${LIBKQUEUE_LIBRARIES}
    SOURCES
    BPF_Program.cc
    Component.cc
    Manager.cc
    Packet.cc
    PktDumper.cc
    PktSrc.cc)

add_subdirectory(pcap)
add_subdirectory(af_packet)
