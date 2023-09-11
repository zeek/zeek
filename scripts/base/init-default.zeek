##! This script loads everything in the base/ script directory.  If you want
##! to run Zeek without all of these scripts loaded by default, you can use
##! the ``-b`` (``--bare-mode``) command line argument.  You can also copy the
##! "@load" lines from this script to your own script to load only the scripts
##! that you actually want.

@load base/utils/site
@load base/utils/active-http
@load base/utils/addrs
@load base/utils/backtrace
@load base/utils/conn-ids
@load base/utils/dir
@load base/utils/directions-and-hosts
@load base/utils/email
@load base/utils/exec
@load base/utils/files
@load base/utils/geoip-distance
@load base/utils/hash_hrw
@load base/utils/numbers
@load base/utils/packages
@load base/utils/paths
@load base/utils/patterns
@load base/utils/queue
@load base/utils/strings
@load base/utils/thresholds
@load base/utils/time
@load base/utils/urls

# This has some deep interplay between types and BiFs so it's
# loaded in base/init-bare.zeek
#@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/analyzer
@load base/frameworks/signatures
@load base/frameworks/packet-filter
@load base/frameworks/software
@load base/frameworks/control
@load base/frameworks/cluster
@load base/frameworks/intel
@load base/frameworks/config
@load base/frameworks/reporter
@load base/frameworks/sumstats
@load base/frameworks/tunnels
@load base/frameworks/openflow
@load base/frameworks/netcontrol
@load base/frameworks/telemetry
@load base/frameworks/storage

@if ( have_spicy() )
@load base/frameworks/spicy
@endif

@load base/protocols/conn
@load base/protocols/dce-rpc
@load base/protocols/dhcp
@load base/protocols/dnp3
@load base/protocols/dns
@load base/protocols/finger
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/imap
@load base/protocols/irc
@load base/protocols/krb
@load base/protocols/ldap
@load base/protocols/modbus
@load base/protocols/mqtt
@load base/protocols/mysql
@load base/protocols/ntlm
@load base/protocols/ntp
@load base/protocols/pop3
@load base/protocols/quic
@load base/protocols/radius
@load base/protocols/rdp
@load base/protocols/rfb
@load base/protocols/sip
@load base/protocols/snmp
@load base/protocols/smb
@load base/protocols/smtp
@load base/protocols/socks
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/syslog
@load base/protocols/websocket
@load base/protocols/tunnels
@load base/protocols/xmpp

@load base/files/pe
@load base/files/hash
@load base/files/extract
@load base/files/x509

@load base/misc/find-checksum-offloading
@load base/misc/find-filtered-trace
@load base/misc/installation
@load base/misc/version
