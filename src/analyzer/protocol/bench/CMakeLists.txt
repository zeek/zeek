spicy_add_analyzer(NAME SpicyBench SOURCES spicybench.spicy spicybench.evt)

zeek_add_plugin(
    Zeek
    BinpacBench
    SOURCES
    BinpacBench.cc
    Plugin.cc
    BIFS
    events.bif
    PAC
    bench.pac)
