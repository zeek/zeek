
include(BroPlugin)

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

bro_plugin_begin(Bro BitTorrent)
bro_plugin_cc(BitTorrent.cc BitTorrentTracker.cc Plugin.cc)
bro_plugin_bif(events.bif)
bro_plugin_pac(bittorrent.pac bittorrent-analyzer.pac bittorrent-protocol.pac)
bro_plugin_end()
