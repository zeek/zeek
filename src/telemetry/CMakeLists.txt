zeek_add_subdir_library(
    telemetry
    SOURCES
        Manager.cc
)

# Treat BIFs as builtin (alternative mode).
bif_target(telemetry.bif)
