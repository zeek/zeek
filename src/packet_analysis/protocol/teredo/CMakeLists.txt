include(ZeekPlugin)

zeek_plugin_begin(Zeek Teredo)
zeek_plugin_cc(Teredo.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_bif(functions.bif)
zeek_plugin_end()
