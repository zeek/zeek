cmake_minimum_required(VERSION 3.15 FATAL_ERROR)

project(ZeekPluginEventLatency)

include(ZeekPlugin)

zeek_add_plugin(
    Zeek EventLatency
    SOURCES src/Plugin.cc SCRIPT_FILES scripts/__load__.zeek)
