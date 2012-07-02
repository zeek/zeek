##! This script loads everything in the base/ script directory.  If you want
##! to run Bro without all of these scripts loaded by default, you can use
##! the -b (--bare-mode) command line argument.  You can also copy the "@load"
##! lines from this script to your own script to load only the scripts that 
##! you actually want.

@load base/utils/site
@load base/utils/addrs
@load base/utils/conn-ids
@load base/utils/directions-and-hosts
@load base/utils/files
@load base/utils/numbers
@load base/utils/paths
@load base/utils/patterns
@load base/utils/strings
@load base/utils/thresholds

# This has some deep interplay between types and BiFs so it's 
# loaded in base/init-bare.bro
#@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/dpd
@load base/frameworks/signatures
@load base/frameworks/packet-filter
@load base/frameworks/software
@load base/frameworks/communication
@load base/frameworks/control
@load base/frameworks/cluster
@load base/frameworks/metrics
@load base/frameworks/intel
@load base/frameworks/reporter
@load base/frameworks/tunnels

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/irc
@load base/protocols/smtp
@load base/protocols/socks
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/syslog
