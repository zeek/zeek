if (NOT ENABLE_SPICY_SSL)
    zeek_add_plugin(
        Zeek
        SSL
        SOURCES
        SSL.cc
        DTLS.cc
        Plugin.cc
        BIFS
        types.bif
        events.bif
        functions.bif
        consts.bif
        PAC
        tls-handshake.pac
        tls-handshake-protocol.pac
        tls-handshake-analyzer.pac
        ssl-defs.pac
        proc-certificate.pac
        tls-handshake-signed_certificate_timestamp.pac
        PAC
        ssl.pac
        ssl-dtls-analyzer.pac
        ssl-analyzer.pac
        ssl-dtls-protocol.pac
        ssl-protocol.pac
        ssl-defs.pac
        proc-certificate.pac
        PAC
        dtls.pac
        ssl-dtls-analyzer.pac
        dtls-analyzer.pac
        ssl-dtls-protocol.pac
        dtls-protocol.pac
        ssl-defs.pac)

    if (NOT DISABLE_SPICY)
        # Even if we are using the binpac SSL analyzer make sure the Spicy
        # analyzer builds successfully. We use a debug build (`-d`) to perform
        # a faster build.
        add_custom_command(
            OUTPUT spicy-ssl.hlto
            COMMENT "Compiling Spicy SSL analyzer"
            COMMAND spicyz -d spicy/SSL.spicy spicy/SSL.evt spicy/support.cc -o
                    ${CMAKE_CURRENT_BINARY_DIR}/spicy-ssl.hlto
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
            DEPENDS spicyz spicy/SSL.spicy spicy/SSL.evt spicy/support.cc)
        add_custom_target(spicy-ssl ALL DEPENDS spicy-ssl.hlto)
    endif ()
else ()
    add_subdirectory(spicy)
    zeek_add_plugin(Zeek SSL SOURCES Plugin.cc BIFS functions.bif)
endif ()
