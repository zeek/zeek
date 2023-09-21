if (OPENSSL_VERSION VERSION_GREATER_EQUAL "1.1.0")
    spicy_add_analyzer(NAME QUIC PACKAGE_NAME QUIC SOURCES QUIC.spicy QUIC.evt decrypt_crypto.cc)

    # spicy_QUIC target is conditionally created by spicy_add_analyzer()
    if (TARGET spicy_QUIC)
        # I don't think this is actually needed as there's an unconditional
        # include_directories(BEFORE ${OPENSSL_INCLUDE_DIR}) at the top-level.
        target_include_directories(spicy_QUIC PRIVATE "${OPENSSL_INCLUDE_DIR}")
    endif ()
else ()
    message(
        STATUS
            "Warning: QUIC analyzer unavailable - requires OpenSSL 1.1 or later (found ${OPENSSL_VERSION})"
    )
endif ()

# Allow tests to introspect availability of the QUIC analyzer.
if (TARGET spicy_QUIC)
    set(ZEEK_HAVE_ANALYZER_QUIC yes CACHE INTERNAL "Zeek has QUIC protocol parser support")
else ()
    set(ZEEK_HAVE_ANALYZER_QUIC no CACHE INTERNAL "Zeek has QUIC protocol parser support")
endif ()
