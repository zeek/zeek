include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(telemetry_SRCS
    Counter.cc
    Manager.cc
    MetricFamily.cc
)

# bif_target(comm.bif)
# bif_target(data.bif)
# bif_target(messaging.bif)
# bif_target(store.bif)

bro_add_subdir_library(telemetry ${telemetry_SRCS})

