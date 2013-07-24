
include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(probabilistic_SRCS
    BitVector.cc
    BloomFilter.cc
    CounterVector.cc
    Hasher.cc
    HyperLogLog.cc)

bif_target(bloom-filter.bif)
set(BIF_OUTPUT_CC_SAVE ${BIF_OUTPUT_CC})
bif_target(hyper-loglog.bif)

bro_add_subdir_library(probabilistic ${probabilistic_SRCS} ${BIF_OUTPUT_CC_SAVE} ${BIF_OUTPUT_CC})
add_dependencies(bro_probabilistic generate_outputs)
