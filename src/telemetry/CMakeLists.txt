zeek_add_subdir_library(
    telemetry
    SOURCES
    Counter.cc
    Gauge.cc
    Histogram.cc
    Manager.cc
    Opaques.cc
    ProcessStats.cc
    Utils.cc)

# BIFs are loaded in src/CMakeLists.txt so they are available early on, to allow
# our own frameworks to establish metrics in the script layer.

# We don't need to include the civetweb headers across the whole project, only
# here in the telemetry framework.
target_include_directories(
    zeek_telemetry_obj BEFORE
    PUBLIC ${PROJECT_SOURCE_DIR}/auxil/prometheus-cpp/3rdparty/civetweb/include)
