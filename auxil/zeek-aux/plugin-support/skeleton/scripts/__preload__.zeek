#
# This is loaded automatically at Zeek startup once the plugin gets activated,
# but before any of the BiFs that the plugin defines become available.
#
# This is primarily for defining types that BiFs already depend on.  If you
# need to do any other unconditional initialization, that should go into
# __load__.zeek instead.
#

@load ./types

