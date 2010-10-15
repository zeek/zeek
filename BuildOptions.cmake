#--------------------------------------------------------------------#
#                                                                    #
#                          Bro - Build Setup                         #
#                                                                    #
#--------------------------------------------------------------------#

# The installation directory
set(CMAKE_INSTALL_PREFIX /usr/local
    CACHE STRING "Installation directory" FORCE)

# The installation subdirectory for Bro policy files
set(DATADIR share/bro
     CACHE STRING "Installation subdirectory for Bro policy files" FORCE)

# Enable active mapping processing
set(ACTIVE_MAPPING false
    CACHE STRING "enable active mapping processing" FORCE)

# Enable IPv6 processing
set(BROv6 false
    CACHE STRING "enable IPv6 processing" FORCE)

# Enable DFA state expiration
set(EXPIRE_DFA_STATES false
    CACHE STRING "enable DFA state expiration" FORCE)

# Enable select-based mainloop
set(USE_SELECT_LOOP false
    CACHE STRING "enable select-based main loop" FORCE)

# Enable non-blocking DNS support
set(USE_NB_DNS false
    CACHE STRING "enable non-blocking DNS support" FORCE)

# Enable use of int64 (long long) for integers
set(USE_INT64 false
    CACHE STRING "enable use of int64 (long long) for integers" FORCE)

# Uncomment to specify a custom prefix that contains the libpcap installation.
#set(PCAP_ROOT path/to/your/pcap)

# Uncomment to specify a custom directory that contains libpcap headers.
#set(PCAP_INCLUDEDIR path/to/your/pcap/include)

# Uncomment to specify a custom directory that contains the libpcap library.
#set(PCAP_LIBRARYDIR path/to/your/pcap/lib)

# Attempt to use non-blocking DNS support by default
set(USE_NB_DNS true
    CACHE BOOL "Use non-blocking DNS support" FORCE)
