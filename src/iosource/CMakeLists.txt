zeek_add_subdir_library(
    iosource
    SOURCES
    BPF_Program.cc
    Component.cc
    Manager.cc
    Packet.cc
    PktDumper.cc
    PktSrc.cc)

add_subdirectory(pcap)
