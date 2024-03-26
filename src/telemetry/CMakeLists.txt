zeek_add_subdir_library(
    telemetry
    SOURCES
    Manager.cc
    Opaques.cc
    ProcessStats.cc
    Utils.cc
    BIFS
    telemetry.bif)

# We don't need to include the civetweb headers across the whole project, only
# here in the telemetry framework.
target_include_directories(
    zeek_telemetry_obj BEFORE
    PUBLIC ${PROJECT_SOURCE_DIR}/auxil/prometheus-cpp/3rdparty/civetweb/include)
