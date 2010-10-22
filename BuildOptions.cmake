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
set(CMAKE_INSTALL_PREFIX /usr/local/bro
    CACHE STRING "Installation directory" FORCE)

# The installation subdirectory for Bro policy files
# TODO: add to configure wrapper as '--datadir'
set(DATADIR share/bro
     CACHE STRING "Installation subdirectory for Bro policy files" FORCE)

##
## Optional Features
##

# TODO: add to configure wrapper as '--enable-debug'
set(ENABLE_DEBUG false
    CACHE STRING "Compile with debugging symbols" FORCE)

# TODO: add to configure wrapper as '--enable-release'
set(ENABLE_RELEASE false
    CACHE STRING "Use -O3 compiler optimizations" FORCE)

# TODO: add to configure wrapper as '--bro-v6'
# Eventually, this should be always on and won't be needed as an option
set(BROv6 false
    CACHE STRING "enable IPv6 processing" FORCE)

# TODO: add to configure wrapper as '--enable-perftools'
set(ENABLE_PERFTOOLS false
    CACHE STRING "use Google's perftools" FORCE)

##
## Configure Dependencies for Non-Standard Paths
##

# Uncomment to specify a custom prefix containing the OpenSSL installation.
#set(OPENSSL_ROOT_DIR path/to/your/openssl)

# Uncomment to specify a custom prefix containing the BIND installation.
#set(BIND_ROOT_DIR path/to/your/bind)

# Uncomment to specify a custom prefix that contains the libpcap installation.
#set(PCAP_ROOT_DIR path/to/your/pcap)

# Uncomment to specify a custom prefix containing the BinPAC installation.
#set(BinPAC_ROOT_DIR path/to/your/binpac)

# Uncomment to prefer building BinPAC from existing sources rather than
# use an existing installation (i.e. you have initialized Bro's BinPAC
# git submodule and updated sources local to the Bro source tree)
#set(BinPAC_PREFER_BUILD true)

# Comment this if local build of BinPAC should be scheduled for installation
set(BinPAC_SKIP_INSTALL true)

# Uncomment to specify a custom prefix containing the libmagic installation.
#set(LibMagic_ROOT_DIR path/to/your/libmagic)

# Uncomment to specify a custom prefix containing the libGeoIP installation.
#set(LibGeoIP_ROOT_DIR path/to/your/libGeoIP)

# Uncomment to specify a custom prefix containing Google Perftools installation.
#set(GooglePerftools_ROOT_DIR path/to/your/google-perftools)
