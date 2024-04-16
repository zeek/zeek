# This is not an actual analyzer, but used by others. We still maintain it here
# along with the other analyzers because conceptually it's also parsing a
# protocol just like them. The current structure is merely a left-over from when
# this code was written.

zeek_add_plugin(
    Zeek
    MIME
    SOURCES
    MIME.cc
    Plugin.cc
    BIFS
    consts.bif
    events.bif)
