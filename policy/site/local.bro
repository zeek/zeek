##! Local site policy. Customize as appropriate.

# DPD should typically be loaded.  It enables the subsystem for detecting
# protocols on non-standard ports and attaching the appropriate analyzer.
@load frameworks/dpd

# Load some of the commonly used frameworks.
@load frameworks/notice
@load frameworks/signatures
@load frameworks/metrics
@load frameworks/intel
@load frameworks/software
@load frameworks/reporter

# Load a few extra scripts that aren't loaded by default.
@load frameworks/packet-filter/netstats
@load misc/loaded-scripts

# Load most of the protocol analysis scripts.
@load protocols/conn
@load protocols/dns
@load protocols/ftp
@load protocols/http
@load protocols/irc
@load protocols/mime 
@load protocols/smtp
@load protocols/ssh
@load protocols/ssl
@load protocols/syslog

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults
