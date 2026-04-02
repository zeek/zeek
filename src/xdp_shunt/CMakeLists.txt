option(ENABLE_XDP_SHUNT "Enable the XDP Shunter plugin" OFF)

if (ENABLE_XDP_SHUNT)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBXDP libxdp)
    pkg_check_modules(LIBBPF libbpf)

    if (POLICY CMP0116)
        cmake_policy(SET CMP0116 NEW)
    endif ()

    if (NOT LIBXDP_FOUND OR NOT LIBBPF_FOUND)
        message(FATAL_ERROR "XDP Shunter enabled, but libxdp/libbpf not found.")
    endif ()

    set(BPF_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}/bpf")
    set(BPF_SOURCE "${CMAKE_CURRENT_SOURCE_DIR}/bpf/filter.c")
    set(BPF_OBJECT "${BPF_OUTPUT_DIR}/filter.o")
    set(BPF_SKELETON "${BPF_OUTPUT_DIR}/filter.skel.h")

    zeek_add_plugin(
        Zeek XDP_Shunter
        INCLUDE_DIRS ${LIBXDP_INCLUDE_DIRS} ${LIBBPF_INCLUDE_DIRS} ${BPF_OUTPUT_DIR}
        DEPENDENCIES ${LIBXDP_LIBRARIES} ${LIBBPF_LIBRARIES}
        SOURCES Plugin.cc XDPProgram.cc ShuntUtil.cc bpf/UserXDP.cc ${BPF_SKELETON}
        BIFS shunter.bif ip_pair_shunter.bif conn_id_shunter.bif)

    find_program(CLANG_EXECUTABLE clang REQUIRED)
    find_program(BPF_GCC_EXECUTABLE NAMES bpf-gcc bpf-unknown-none-gcc)
    find_program(BPFTOOL_EXECUTABLE bpftool REQUIRED)

    if (NOT CLANG_EXECUTABLE AND NOT BPF_GCC_EXECUTABLE)
        message(FATAL_ERROR "clang or bpf-gcc are required to be in your PATH to build this plugin")
    endif ()

    file(MAKE_DIRECTORY ${BPF_OUTPUT_DIR})
    set(BPF_DEPFILE "${BPF_OBJECT}.d")

    if (CLANG_EXECUTABLE)
        message(STATUS "Compiling bpf filter with clang")
        add_custom_command(
            OUTPUT ${BPF_OBJECT}
            COMMAND ${CLANG_EXECUTABLE} -g -O2 -target bpf -D__BPF_BUILD__ -MD -MF ${BPF_DEPFILE} -c
                    ${BPF_SOURCE} -o ${BPF_OBJECT}
            DEPENDS ${BPF_SOURCE}
            DEPFILE ${BPF_DEPFILE}
            COMMENT "Compiling BPF code ${BPF_SOURCE}")
    elseif (BPF_GCC_EXECUTABLE)
        message(STATUS "Compiling bpf filter with bpf-gcc")
        add_custom_command(
            OUTPUT ${BPF_OBJECT}
            COMMAND ${BPF_GCC_EXECUTABLE} -std=gnu11 -gbtf -O2 -D__BPF_BUILD__ -I/usr/include -MD
                    -MF ${BPF_DEPFILE} -c ${BPF_SOURCE} -o ${BPF_OBJECT}
            DEPENDS ${BPF_SOURCE}
            DEPFILE ${BPF_DEPFILE}
            COMMENT "Compiling BPF code ${BPF_SOURCE}")
    endif ()

    add_custom_command(
        OUTPUT ${BPF_SKELETON}
        COMMAND bash -c "${BPFTOOL_EXECUTABLE} gen skeleton ${BPF_OBJECT} > ${BPF_SKELETON}"
        DEPENDS ${BPF_OBJECT}
        COMMENT "Generating BPF skeleton ${BPF_SKELETON}"
        VERBATIM)

    get_filename_component(PLUGIN_STEM ${CMAKE_CURRENT_SOURCE_DIR} NAME)
    set(MY_BPF_INSTALL_DEST "${ZEEK_PLUGIN_DIR}/${PLUGIN_STEM}/bpf")

    install(FILES ${BPF_OBJECT} DESTINATION "${MY_BPF_INSTALL_DEST}" COMPONENT Plugin)

    set(ZEEK_HAVE_XDP_SHUNT yes CACHE INTERNAL "")
endif ()
