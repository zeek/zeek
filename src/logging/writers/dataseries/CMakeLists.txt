
include(BroPlugin)

find_package(Lintel)
find_package(DataSeries)
find_package(LibXML2)

if (NOT DISABLE_DATASERIES AND
    LINTEL_FOUND AND DATASERIES_FOUND AND LIBXML2_FOUND)

    include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

    bro_plugin_begin(Bro DataSeriesWriter)
    bro_plugin_cc(DataSeries.cc Plugin.cc)
    bro_plugin_bif(dataseries.bif)
    bro_plugin_end()

endif()

