zeek_add_plugin(
    Zeek HTTP
    SOURCES HTTP.cc Plugin.cc
    BIFS consts.bif events.bif functions.bif)
