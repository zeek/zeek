# Not a plugin right now.
#
# zeek_add_plugin(
#    Zeek
#    Cluster_Serializer_Broker
#    INCLUDE_DIRS
#    ${CMAKE_CURRENT_SOURCE_DIR}
#    ${CMAKE_CURRENT_BINARY_DIR}
#    DEPENDENCIES
#    SOURCES
#    Plugin.cc)

zeek_add_subdir_library(binary-serialization-format INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
                        ${CMAKE_CURRENT_BINARY_DIR} SOURCES Serializer.cc)
