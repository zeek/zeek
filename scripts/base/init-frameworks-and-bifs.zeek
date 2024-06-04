# Load these frameworks here because they use fairly deep integration with
# BiFs and script-land defined types.  They are also more likely to
# make use of calling BIFs for variable initializations, and that
# can't be done until init-bare.zeek has been loaded completely (hence
# the separate file).
@load base/frameworks/logging
@load base/frameworks/broker
@load base/frameworks/supervisor
@load base/frameworks/input
@load base/frameworks/cluster
@load base/frameworks/config
@load base/frameworks/analyzer
@load base/frameworks/files
@load base/frameworks/telemetry/options

@load base/bif

# Load BiFs defined by plugins.
@load base/bif/plugins

@if ( have_spicy() )
@load base/frameworks/spicy/init-framework
@endif

# This sets up secondary/subdir BIFs such that they can be used by any
# further scripts within their global initializations and is intended to be
# the last thing done within this script.  It's called within @if simply so
# that it executes at parse-time.  An alternative way to do that is to call
# it during a global variable assignment/initialization.  Formally adding a
# @run directive to the language whose sole purpose is parse-time code
# execution would be another idea.
@if ( __init_secondary_bifs() )
@endif
