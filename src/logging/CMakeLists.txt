
include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(writers)

set(logging_SRCS
    Component.cc
    Manager.cc
    WriterBackend.cc
    WriterFrontend.cc
    Tag.cc
)

bif_target(logging.bif)

bro_add_subdir_library(logging ${logging_SRCS} ${BIF_OUTPUT_CC})
add_dependencies(bro_logging generate_outputs)

