##! This loads Management framework functionality needed by both the controller
##! and agents. Note that there's no notion of loading "the Management
##! framework" -- one always loads "management/controller" or
##! "management/agent". This __load__ script exists only to simplify loading all
##! common functionality.

@load ./config
@load ./log
@load ./persistence
@load ./request
@load ./types
@load ./util
