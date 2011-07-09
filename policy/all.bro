##! This script only aims at loading all of the base analysis scripts.

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

@load frameworks/metrics
@load frameworks/notice
@load frameworks/signatures
@load frameworks/software
@load frameworks/reporter
@load frameworks/cluster

@load tuning/defaults

@load support/loaded-scripts
