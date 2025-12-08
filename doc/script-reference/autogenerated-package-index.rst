:doc:`base/packet-protocols </scripts/base/packet-protocols/index>`


:doc:`base/packet-protocols/root </scripts/base/packet-protocols/root/index>`


:doc:`base/packet-protocols/ip </scripts/base/packet-protocols/ip/index>`


:doc:`base/packet-protocols/skip </scripts/base/packet-protocols/skip/index>`


:doc:`base/packet-protocols/ethernet </scripts/base/packet-protocols/ethernet/index>`


:doc:`base/packet-protocols/fddi </scripts/base/packet-protocols/fddi/index>`


:doc:`base/packet-protocols/ieee802_11 </scripts/base/packet-protocols/ieee802_11/index>`


:doc:`base/packet-protocols/ieee802_11_radio </scripts/base/packet-protocols/ieee802_11_radio/index>`


:doc:`base/packet-protocols/linux_sll </scripts/base/packet-protocols/linux_sll/index>`


:doc:`base/packet-protocols/linux_sll2 </scripts/base/packet-protocols/linux_sll2/index>`


:doc:`base/packet-protocols/nflog </scripts/base/packet-protocols/nflog/index>`


:doc:`base/packet-protocols/null </scripts/base/packet-protocols/null/index>`


:doc:`base/packet-protocols/ppp </scripts/base/packet-protocols/ppp/index>`


:doc:`base/packet-protocols/ppp_serial </scripts/base/packet-protocols/ppp_serial/index>`


:doc:`base/packet-protocols/pppoe </scripts/base/packet-protocols/pppoe/index>`


:doc:`base/packet-protocols/vlan </scripts/base/packet-protocols/vlan/index>`


:doc:`base/packet-protocols/mpls </scripts/base/packet-protocols/mpls/index>`


:doc:`base/packet-protocols/pbb </scripts/base/packet-protocols/pbb/index>`


:doc:`base/packet-protocols/vntag </scripts/base/packet-protocols/vntag/index>`


:doc:`base/packet-protocols/udp </scripts/base/packet-protocols/udp/index>`


:doc:`base/packet-protocols/tcp </scripts/base/packet-protocols/tcp/index>`


:doc:`base/packet-protocols/icmp </scripts/base/packet-protocols/icmp/index>`


:doc:`base/packet-protocols/llc </scripts/base/packet-protocols/llc/index>`


:doc:`base/packet-protocols/novell_802_3 </scripts/base/packet-protocols/novell_802_3/index>`


:doc:`base/packet-protocols/snap </scripts/base/packet-protocols/snap/index>`


:doc:`base/packet-protocols/gre </scripts/base/packet-protocols/gre/index>`


:doc:`base/packet-protocols/iptunnel </scripts/base/packet-protocols/iptunnel/index>`


:doc:`base/packet-protocols/ayiya </scripts/base/packet-protocols/ayiya/index>`


:doc:`base/packet-protocols/geneve </scripts/base/packet-protocols/geneve/index>`


:doc:`base/packet-protocols/vxlan </scripts/base/packet-protocols/vxlan/index>`


:doc:`base/packet-protocols/teredo </scripts/base/packet-protocols/teredo/index>`


:doc:`base/packet-protocols/gtpv1 </scripts/base/packet-protocols/gtpv1/index>`


:doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

   The logging framework provides a flexible key-value based logging interface.

:doc:`base/frameworks/logging/postprocessors </scripts/base/frameworks/logging/postprocessors/index>`

   Support for postprocessors in the logging framework.

:doc:`base/frameworks/broker </scripts/base/frameworks/broker/index>`

   The Broker communication framework facilitates connecting to remote Zeek
   instances to share state and transfer events.

:doc:`base/frameworks/supervisor </scripts/base/frameworks/supervisor/index>`


:doc:`base/frameworks/input </scripts/base/frameworks/input/index>`

   The input framework provides a way to read previously stored data either as
   an event stream or into a Zeek table.

:doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`

   The cluster framework provides for establishing and controlling a cluster
   of Zeek instances.

:doc:`base/frameworks/control </scripts/base/frameworks/control/index>`

   The control framework provides the foundation for providing "commands"
   that can be taken remotely at runtime to modify a running Zeek instance
   or collect information from the running instance.

:doc:`base/frameworks/config </scripts/base/frameworks/config/index>`

   The configuration framework provides a way to change the Zeek configuration
   in "option" values at run-time.

:doc:`base/frameworks/analyzer </scripts/base/frameworks/analyzer/index>`

   The analyzer framework allows to dynamically enable or disable Zeek's
   protocol analyzers, as well as to manage the well-known ports which
   automatically activate a particular analyzer for new connections.

:doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

   The file analysis framework provides an interface for driving the analysis
   of files, possibly independent of any network protocol over which they're
   transported.

:doc:`base/frameworks/files/magic </scripts/base/frameworks/files/magic/index>`


:doc:`base/bif </scripts/base/bif/index>`


:doc:`base/bif/plugins </scripts/base/bif/plugins/index>`


:doc:`base/frameworks/reporter </scripts/base/frameworks/reporter/index>`

   This framework is intended to create an output and filtering path for
   internally generated messages/warnings/errors.

:doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`

   The notice framework enables Zeek to "notice" things which are odd or
   potentially bad, leaving it to the local configuration to define which
   of them are actionable.  This decoupling of detection and reporting allows
   Zeek to be customized to the different needs that sites have.

:doc:`base/frameworks/signatures </scripts/base/frameworks/signatures/index>`

   The signature framework provides for doing low-level pattern matching.  While
   signatures are not Zeek's preferred detection tool, they sometimes come in
   handy and are closer to what many people are familiar with from using
   other NIDS.

:doc:`base/frameworks/packet-filter </scripts/base/frameworks/packet-filter/index>`

   The packet filter framework supports how Zeek sets its BPF capture filter.

:doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

   The software framework provides infrastructure for maintaining a table
   of software versions seen on the network. The version parsing itself
   is carried out by external protocol-specific scripts that feed into
   this framework.

:doc:`base/frameworks/intel </scripts/base/frameworks/intel/index>`

   The intelligence framework provides a way to store and query intelligence
   data (such as IP addresses or strings). Metadata can also be associated
   with the intelligence.

:doc:`base/frameworks/sumstats </scripts/base/frameworks/sumstats/index>`

   The summary statistics framework provides a way to summarize large streams
   of data into simple reduced measurements.

:doc:`base/frameworks/sumstats/plugins </scripts/base/frameworks/sumstats/plugins/index>`

   Plugins for the summary statistics framework.

:doc:`base/frameworks/tunnels </scripts/base/frameworks/tunnels/index>`

   The tunnels framework handles the tracking/logging of tunnels (e.g. Teredo,
   AYIYA, or IP-in-IP such as 6to4 where "IP" is either IPv4 or IPv6).

:doc:`base/frameworks/openflow </scripts/base/frameworks/openflow/index>`

   The OpenFlow framework exposes the data structures and functions
   necessary to interface to OpenFlow capable hardware.

:doc:`base/frameworks/openflow/plugins </scripts/base/frameworks/openflow/plugins/index>`

   Plugins for the OpenFlow framework.

:doc:`base/frameworks/netcontrol </scripts/base/frameworks/netcontrol/index>`

   The NetControl framework provides a way for Zeek to interact with networking
   hard- and software, e.g. for dropping and shunting IP addresses/connections,
   etc.

:doc:`base/frameworks/netcontrol/plugins </scripts/base/frameworks/netcontrol/plugins/index>`

   Plugins for the NetControl framework.

:doc:`base/frameworks/telemetry </scripts/base/frameworks/telemetry/index>`


:doc:`base/frameworks/storage </scripts/base/frameworks/storage/index>`


:doc:`base/frameworks/spicy </scripts/base/frameworks/spicy/index>`


:doc:`base/protocols/conn </scripts/base/protocols/conn/index>`

   Support for connection (TCP, UDP, or ICMP) analysis.

:doc:`base/protocols/dce-rpc </scripts/base/protocols/dce-rpc/index>`

   Support for DCE/RPC (Distributed Computing Environment/Remote Procedure
   Calls) protocol analysis.

:doc:`base/protocols/dhcp </scripts/base/protocols/dhcp/index>`

   Support for Dynamic Host Configuration Protocol (DHCP) analysis.

:doc:`base/protocols/dnp3 </scripts/base/protocols/dnp3/index>`

   Support for Distributed Network Protocol (DNP3) analysis.

:doc:`base/protocols/dns </scripts/base/protocols/dns/index>`

   Support for Domain Name System (DNS) protocol analysis.

:doc:`base/protocols/finger </scripts/base/protocols/finger/index>`


:doc:`base/protocols/ftp </scripts/base/protocols/ftp/index>`

   Support for File Transfer Protocol (FTP) analysis.

:doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

   Support for Secure Sockets Layer (SSL)/Transport Layer Security(TLS) protocol analysis.

:doc:`base/files/x509 </scripts/base/files/x509/index>`

   Support for X509 certificates with the file analysis framework.
   Also supports parsing OCSP requests and responses.

:doc:`base/files/hash </scripts/base/files/hash/index>`

   Support for file hashes with the file analysis framework.

:doc:`base/protocols/http </scripts/base/protocols/http/index>`

   Support for Hypertext Transfer Protocol (HTTP) analysis.

:doc:`base/protocols/imap </scripts/base/protocols/imap/index>`

   Support for the Internet Message Access Protocol (IMAP).
   
   Note that currently the IMAP analyzer only supports analyzing IMAP sessions
   until they do or do not switch to TLS using StartTLS. Hence, we do not get
   mails from IMAP sessions, only X509 certificates.

:doc:`base/protocols/irc </scripts/base/protocols/irc/index>`

   Support for Internet Relay Chat (IRC) protocol analysis.

:doc:`base/protocols/krb </scripts/base/protocols/krb/index>`

   Support for Kerberos protocol analysis.

:doc:`base/protocols/ldap </scripts/base/protocols/ldap/index>`


:doc:`base/protocols/modbus </scripts/base/protocols/modbus/index>`

   Support for Modbus protocol analysis.

:doc:`base/protocols/mqtt </scripts/base/protocols/mqtt/index>`

   Support for MQTT protocol analysis.

:doc:`base/protocols/mysql </scripts/base/protocols/mysql/index>`

   Support for MySQL protocol analysis.

:doc:`base/protocols/ntlm </scripts/base/protocols/ntlm/index>`

   Support for NT LAN Manager (NTLM) protocol analysis.

:doc:`base/protocols/ntp </scripts/base/protocols/ntp/index>`


:doc:`base/protocols/pop3 </scripts/base/protocols/pop3/index>`

   Support for POP3 (Post Office Protocol) protocol analysis.

:doc:`base/protocols/postgresql </scripts/base/protocols/postgresql/index>`


:doc:`base/protocols/quic </scripts/base/protocols/quic/index>`


:doc:`base/protocols/radius </scripts/base/protocols/radius/index>`

   Support for RADIUS protocol analysis.

:doc:`base/protocols/rdp </scripts/base/protocols/rdp/index>`

   Support for Remote Desktop Protocol (RDP) analysis.

:doc:`base/protocols/redis </scripts/base/protocols/redis/index>`


:doc:`base/protocols/rfb </scripts/base/protocols/rfb/index>`

   Support for Remote FrameBuffer analysis.  This includes all VNC servers.

:doc:`base/protocols/sip </scripts/base/protocols/sip/index>`

   Support for Session Initiation Protocol (SIP) analysis.

:doc:`base/protocols/snmp </scripts/base/protocols/snmp/index>`

   Support for Simple Network Management Protocol (SNMP) analysis.

:doc:`base/protocols/smb </scripts/base/protocols/smb/index>`

   Support for SMB protocol analysis.

:doc:`base/protocols/smtp </scripts/base/protocols/smtp/index>`

   Support for Simple Mail Transfer Protocol (SMTP) analysis.

:doc:`base/protocols/socks </scripts/base/protocols/socks/index>`

   Support for Socket Secure (SOCKS) protocol analysis.

:doc:`base/protocols/ssh </scripts/base/protocols/ssh/index>`

   Support for SSH protocol analysis.

:doc:`base/protocols/syslog </scripts/base/protocols/syslog/index>`

   Support for Syslog protocol analysis.

:doc:`base/protocols/websocket </scripts/base/protocols/websocket/index>`


:doc:`base/protocols/tunnels </scripts/base/protocols/tunnels/index>`

   Provides DPD signatures for tunneling protocols that otherwise
   wouldn't be detected at all.

:doc:`base/protocols/xmpp </scripts/base/protocols/xmpp/index>`

   Support for the Extensible Messaging and Presence Protocol (XMPP).
   
   Note that currently the XMPP analyzer only supports analyzing XMPP sessions
   until they do or do not switch to TLS using StartTLS. Hence, we do not get
   actual chat information from XMPP sessions, only X509 certificates.

:doc:`base/files/pe </scripts/base/files/pe/index>`

   Support for Portable Executable (PE) file analysis.

:doc:`base/files/extract </scripts/base/files/extract/index>`

   Support for extracting files with the file analysis framework.

:doc:`builtin-plugins </scripts/builtin-plugins/index>`


:doc:`builtin-plugins/Zeek_JavaScript </scripts/builtin-plugins/Zeek_JavaScript/index>`


:doc:`zeekygen </scripts/zeekygen/index>`

   This package is loaded during the process which automatically generates
   reference documentation for all Zeek scripts (i.e. "Zeekygen").  Its only
   purpose is to provide an easy way to load all known Zeek scripts plus any
   extra scripts needed or used by the documentation process.

:doc:`policy/frameworks/cluster/backend/broker </scripts/policy/frameworks/cluster/backend/broker/index>`


:doc:`policy/frameworks/cluster/backend/zeromq </scripts/policy/frameworks/cluster/backend/zeromq/index>`


:doc:`policy/frameworks/management/agent </scripts/policy/frameworks/management/agent/index>`


:doc:`policy/frameworks/management </scripts/policy/frameworks/management/index>`


:doc:`policy/frameworks/management/controller </scripts/policy/frameworks/management/controller/index>`


:doc:`policy/frameworks/management/supervisor </scripts/policy/frameworks/management/supervisor/index>`


:doc:`policy/frameworks/intel/seen </scripts/policy/frameworks/intel/seen/index>`

   Scripts that send data to the intelligence framework.

:doc:`policy/frameworks/notice </scripts/policy/frameworks/notice/index>`


:doc:`policy/frameworks/storage/backend/redis </scripts/policy/frameworks/storage/backend/redis/index>`


:doc:`policy/frameworks/storage/backend/sqlite </scripts/policy/frameworks/storage/backend/sqlite/index>`


:doc:`policy/integration/collective-intel </scripts/policy/integration/collective-intel/index>`

   The scripts in this module are for deeper integration with the
   Collective Intelligence Framework (CIF) since Zeek's Intel framework
   doesn't natively behave the same as CIF nor does it store and maintain
   the same data in all cases.

:doc:`policy/misc/detect-traceroute </scripts/policy/misc/detect-traceroute/index>`

   Detect hosts that are running traceroute.

:doc:`policy/frameworks/management/node </scripts/policy/frameworks/management/node/index>`


