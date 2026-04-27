zeek_add_plugin(
    Zeek Cluster_Serializer_Sans_Broker
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    SOURCES Plugin.cc Serializer.cc Test.cc)
