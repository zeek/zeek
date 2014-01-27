
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})

find_package(Netmap)

if ( NETMAP_FOUND )
    include(BroPlugin)
    include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR} ${NETMAP_INCLUDE_DIR}/sys)
    bro_plugin_begin(Bro Netmap)
    bro_plugin_cc(Source.cc Plugin.cc)
    bro_plugin_end()
endif ()
