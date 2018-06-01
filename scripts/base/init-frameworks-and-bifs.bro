# Load these frameworks here because they use fairly deep integration with
# BiFs and script-land defined types.  They are also more likely to
# make use of calling BIFs for variable initializations, and that
# can't be done until init-bare.bro has been loaded completely (hence
# the separate file).
@load base/frameworks/logging
@load base/frameworks/broker
@load base/frameworks/input
@load base/frameworks/analyzer
@load base/frameworks/files

@load base/bif

# Load BiFs defined by plugins.
@load base/bif/plugins
