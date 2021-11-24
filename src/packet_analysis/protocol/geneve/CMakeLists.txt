include(ZeekPlugin)

zeek_plugin_begin(Zeek Geneve)
zeek_plugin_cc(Geneve.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_end()
