include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(comm_SRCS
    Manager.cc
)

bif_target(comm.bif)

bro_add_subdir_library(comm ${comm_SRCS} ${BIF_OUTPUT_CC})
add_dependencies(bro_comm generate_outputs)
