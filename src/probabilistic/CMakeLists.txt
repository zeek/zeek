zeek_add_subdir_library(
    probabilistic
    SOURCES
        BitVector.cc
        BloomFilter.cc
        CardinalityCounter.cc
        CounterVector.cc
        Hasher.cc
        Topk.cc
)

# Treat BIFs as builtin (alternative mode).
set(bifs
    bloom-filter.bif
    cardinality-counter.bif
    top-k.bif
)
foreach ( bif ${bifs} )
    bif_target(${bif})
endforeach()
