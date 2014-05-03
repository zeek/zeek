
include(BroSubdir)

include_directories(BEFORE
                    ${CMAKE_CURRENT_SOURCE_DIR}
                    ${CMAKE_CURRENT_BINARY_DIR}
)

set(probabilistic_SRCS
    BitVector.cc
    BloomFilter.cc
    CardinalityCounter.cc
    CounterVector.cc
    Hasher.cc
    Topk.cc)

bif_target(bloom-filter.bif)
bif_target(cardinality-counter.bif)
bif_target(top-k.bif)
bro_add_subdir_library(probabilistic ${probabilistic_SRCS})

add_dependencies(bro_probabilistic generate_outputs)
