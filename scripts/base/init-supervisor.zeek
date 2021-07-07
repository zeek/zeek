##! This script loads functionality needed by the supervisor. Zeek only sources
##! this when the supervisor is active (-j). Like init-default.zeek, this isn't
##! loaded in bare mode.

@load base/frameworks/supervisor
