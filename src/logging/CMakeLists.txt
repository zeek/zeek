
include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

include_directories(BEFORE ${CAF_INCLUDE_DIRS})

add_subdirectory(writers)

set(logging_SRCS
    Component.cc
    Manager.cc
    WriterBackend.cc
    WriterFrontend.cc
)

bif_target(logging.bif)

bro_add_subdir_library(logging ${logging_SRCS})
add_dependencies(bro_logging generate_outputs)
