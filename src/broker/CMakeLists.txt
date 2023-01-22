zeek_add_subdir_library(
    comm
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES
        Data.cc
        Manager.cc
        Store.cc
)

# Treat BIFs as builtin (alternative mode).
set(bifs
    comm.bif
    data.bif
    messaging.bif
    store.bif
)
foreach ( bif ${bifs} )
    bif_target(${bif})
endforeach()
