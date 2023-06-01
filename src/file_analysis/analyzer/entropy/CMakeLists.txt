zeek_add_plugin(
    Zeek
    FileEntropy
    SOURCES
    Entropy.cc
    Plugin.cc
    BIFS
    events.bif)
