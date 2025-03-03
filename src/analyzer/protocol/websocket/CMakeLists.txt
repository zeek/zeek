zeek_add_plugin(
    Zeek WebSocket
    SOURCES WebSocket.cc Plugin.cc
    BIFS consts.bif events.bif functions.bif types.bif
    PAC websocket.pac websocket-analyzer.pac websocket-protocol.pac)

if (USE_SPICY_ANALYZERS)
    spicy_add_analyzer(NAME WebSocket SOURCES websocket.spicy websocket.evt unmask.cc)
endif ()
