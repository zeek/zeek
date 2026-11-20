zeek_add_plugin(
    Zeek MySQL
    SOURCES MySQL.cc Plugin.cc
    BIFS consts.bif events.bif
    PAC mysql.pac mysql-analyzer.pac mysql-protocol.pac)
