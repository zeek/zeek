include(ZeekSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(telemetry_SRCS
    Counter.cc
    Gauge.cc
    Histogram.cc
    Manager.cc
    MetricFamily.cc
)

bif_target(telemetry.bif)

bro_add_subdir_library(telemetry ${telemetry_SRCS})

