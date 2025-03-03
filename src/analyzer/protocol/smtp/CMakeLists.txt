zeek_add_plugin(
    Zeek SMTP
    SOURCES SMTP.cc BDAT.cc Plugin.cc
    BIFS consts.bif events.bif functions.bif)
