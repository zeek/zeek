include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

if ( ROCKSDB_INCLUDE_DIR )
    add_definitions(-DHAVE_ROCKSDB)
    include_directories(BEFORE ${ROCKSDB_INCLUDE_DIR})
endif ()

include_directories(BEFORE ${LIBCAF_INCLUDE_DIR_CORE})
include_directories(BEFORE ${LIBCAF_INCLUDE_DIR_IO})

set(comm_SRCS
    Data.cc
    Manager.cc
    Store.cc
)

bif_target(comm.bif)
bif_target(data.bif)
bif_target(messaging.bif)
bif_target(store.bif)

bro_add_subdir_library(brokercomm ${comm_SRCS} ${BIF_OUTPUT_CC})
add_dependencies(bro_brokercomm generate_outputs)
