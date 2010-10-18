#--------------------------------------------------------------------#
#                                                                    #
#                          Bro - Build Setup                         #
#                                                                    #
#--------------------------------------------------------------------#

##
## Installation Settings
##

# The installation directory
# TODO: add to configure wrapper as '--prefix'
set(CMAKE_INSTALL_PREFIX /usr/local
    CACHE STRING "Installation directory" FORCE)

# The installation subdirectory for Bro policy files
# TODO: add to configure wrapper as '--datadir'
set(DATADIR share/bro
     CACHE STRING "Installation subdirectory for Bro policy files" FORCE)

##
## Optional Features
##

# TODO: add to configure wrapper as '--bro-v6'
# Eventually, this should be always on and won't be needed as an option
set(BROv6 false
    CACHE STRING "enable IPv6 processing" FORCE)

set(USE_INT64 true
    CACHE STRING "enable use of int64 (long long) for integers" FORCE)

# TODO: add to configure wrapper as '--enable-debug'
# TODO: make this option do stuff
set(ENABLE_DEBUG false
    CACHE STRING "No compiler optimizations" FORCE)

set(USE_SELECT_LOOP true
    CACHE STRING "enable select-based main loop" FORCE)

# TODO: add to configure wrapper as '--enable-perftools'
# TODO: make this option do stuff
set(ENABLE_PERFTOOLS false
    CACHE STRING "use Google's perftools" FORCE)

set(USE_NB_DNS true
    CACHE BOOL "Use non-blocking DNS support" FORCE)

##
## Configure Dependencies for Non-Standard Paths
##

# Uncomment to specify a custom prefix that contains the libpcap installation.
#set(PCAP_ROOT path/to/your/pcap)

# Uncomment to specify a custom directory that contains libpcap headers.
#set(PCAP_INCLUDEDIR path/to/your/pcap/include)

# Uncomment to specify a custom directory that contains the libpcap library.
#set(PCAP_LIBRARYDIR path/to/your/pcap/lib)

# TODO: more dependencies:
# Flex
# Bison
# BIND8
# Perl?
# BinPAC
#
# OpenSSL
# Libmagic
# LibGeoIP
# Libz
# Endace's DAG tools
