if (${CMAKE_SYSTEM_NAME} MATCHES Linux)
    set(ZEEK_HAVE_AF_PACKET yes CACHE INTERNAL "")

    zeek_add_plugin(Zeek AF_Packet SOURCES Plugin.cc AF_Packet.cc RX_Ring.cc BIFS af_packet.bif)
endif ()
