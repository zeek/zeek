include(ZeekPlugin)

zeek_plugin_begin(Zeek VXLAN)
zeek_plugin_cc(VXLAN.cc Plugin.cc)
zeek_plugin_bif(events.bif)
zeek_plugin_end()
