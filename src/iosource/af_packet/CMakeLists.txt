
cmake_minimum_required(VERSION 2.6.3)

project(Plugin)

include(BroPlugin)

find_package(KernelHeaders)

if ( KERNELHEADERS_FOUND )
	#TODO: Make sure the specified kernel headers are used
    bro_plugin_begin(Bro AF_Packet)
    bro_plugin_cc(src/Plugin.cc)
    bro_plugin_cc(src/AF_Packet.cc)
    bro_plugin_cc(src/RX_Ring.cc)
    bro_plugin_bif(src/af_packet.bif)
    bro_plugin_dist_files(broctl/af_packet.py README COPYING VERSION)
    bro_plugin_end()

    message(STATUS "Kernelheader prefix : ${KERNELHEADERS_ROOT_DIR}")
else ()
    message(FATAL_ERROR "Kernel headers not found.")
endif ()
