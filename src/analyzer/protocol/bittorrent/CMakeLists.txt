
include(ZeekPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

zeek_plugin_begin(Zeek BitTorrent)
zeek_plugin_cc(BitTorrent.cc BitTorrentTracker.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_pac(bittorrent.pac bittorrent-analyzer.pac bittorrent-protocol.pac)
zeek_plugin_end()
