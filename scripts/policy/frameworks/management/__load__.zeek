##! This loads Management framework functionality needed by both the controller
##! and agents. Note that there's no notion of loading "the Management
##! framework" -- one always loads "management/controller" or
##! "management/agent". This __load__ script exists only to simplify loading all
##! common functionality.

@deprecated "Remove in v9.1: Development of the Management Framework has been discontinued and its scripting code will be moved into an external package with Zeek 9.1. See NEWS for more details.";

@load ./config
@load ./log
@load ./persistence
@load ./request
@load ./types
@load ./util
