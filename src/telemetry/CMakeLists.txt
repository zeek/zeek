include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(telemetry_SRCS
    Manager.cc
)

bif_target(telemetry.bif)

bro_add_subdir_library(telemetry ${telemetry_SRCS})
add_dependencies(bro_telemetry generate_outputs)

