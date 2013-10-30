include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(broxygen_SRCS
    Manager.cc
    Document.cc
)

bif_target(broxygen.bif)
bro_add_subdir_library(broxygen ${broxygen_SRCS})

add_dependencies(bro_broxygen generate_outputs)
