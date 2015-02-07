
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro BenchmarkReader)
bro_plugin_cc(Benchmark.cc Plugin.cc)
bro_plugin_bif(benchmark.bif)
bro_plugin_end()
