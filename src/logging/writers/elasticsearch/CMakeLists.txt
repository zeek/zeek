
include(BroPlugin)

find_package(LibCURL)

if (NOT DISABLE_ELASTICSEARCH AND LIBCURL_FOUND)
  include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})
  bro_plugin_begin(Bro ElasticSearchWriter)
  bro_plugin_cc(ElasticSearch.cc Plugin.cc)
  bro_plugin_bif(elasticsearch.bif)
  bro_plugin_link_library(${LibCURL_LIBRARIES})
  bro_plugin_end()
endif()


