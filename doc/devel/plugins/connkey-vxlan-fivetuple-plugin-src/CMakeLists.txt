cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginConnKeyVxlanVniFivetuple)

include(ZeekPlugin)

zeek_add_plugin(
    Zeek ConnKey_Vxlan_Vni_Fivetuple
    SOURCES src/Factory.cc src/Plugin.cc SCRIPT_FILES scripts/__load__.zeek)
