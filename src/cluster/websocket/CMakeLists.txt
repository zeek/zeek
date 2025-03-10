add_subdirectory(auxil)

zeek_add_plugin(
    Zeek Cluster_WebSocket
    INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDENCIES ixwebsocket::ixwebsocket
    SOURCES Plugin.cc WebSocket.cc WebSocket-IXWebSocket.cc
    BIFS events.bif)
