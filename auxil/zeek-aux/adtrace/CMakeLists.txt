find_package(PCAP REQUIRED)

set(adtrace_SRCS adtrace.c)

add_executable(adtrace ${adtrace_SRCS})
target_include_directories(adtrace BEFORE PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(adtrace ${PCAP_LIBRARY})
addauxinstalltarget(adtrace)
