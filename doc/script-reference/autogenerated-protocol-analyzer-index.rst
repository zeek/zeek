Protocol Analyzers
==================

.. zeek:type:: Analyzer::Tag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Analyzer::ANALYZER_BITTORRENT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_BITTORRENTTRACKER Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONNSIZE Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_DCE_RPC Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_DHCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_DNP3_TCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_DNP3_UDP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_DNS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_DNS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_FTP_DATA Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_FTP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_FTP_ADAT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_GNUTELLA Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_GSSAPI Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_HTTP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_ICMP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_IDENT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_IMAP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_IRC Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_IRC_DATA Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_KRB Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_KRB_TCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_RLOGIN Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_RSH Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_LOGIN Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_NVT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_RLOGIN Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_RSH Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_TELNET Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_MODBUS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_MQTT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_MYSQL Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_NCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_NCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_NETBIOSSSN Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_NETBIOSSSN Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_NTLM Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_NTP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_PIA_TCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_PIA_UDP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_POP3 Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_RADIUS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_RDP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_RDPEUDP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_RFB Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_NFS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_RPC Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_MOUNT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_NFS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_PORTMAPPER Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SIP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS_SMB Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SMB Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SMTP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SMTP_BDAT Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SNMP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SOCKS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_FINGER Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_LDAP_TCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_LDAP_UDP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_QUIC Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SYSLOG Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SPICY_WEBSOCKET Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SSH Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_DTLS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_SSL Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTLINE Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_CONTENTS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_TCPSTATS Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_TCP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_UDP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_WEBSOCKET Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_XMPP Analyzer::Tag

      .. zeek:enum:: Analyzer::ANALYZER_ZIP Analyzer::Tag

.. zeek:type:: AllAnalyzers::Tag

   :Type: :zeek:type:`enum`

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_ARP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_AYIYA AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_BITTORRENT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_BITTORRENTTRACKER AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONNSIZE AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_DCE_RPC AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_DHCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_DNP3_TCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_DNP3_UDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_DNS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_DNS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_ETHERNET AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_FDDI AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_FTP_DATA AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_DATA_EVENT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_ENTROPY AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_EXTRACT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_MD5 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_SHA1 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_SHA256 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_FTP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_FTP_ADAT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_GENEVE AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_GNUTELLA AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_GRE AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_GSSAPI AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_GTPV1 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_HTTP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_ICMP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_ICMP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_IDENT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_IEEE802_11 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_IEEE802_11_RADIO AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_IMAP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_IP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_IPTUNNEL AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_IRC AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_IRC_DATA AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_KRB AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_KRB_TCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_LINUXSLL AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_LINUXSLL2 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_LLC AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_RLOGIN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_RSH AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_LOGIN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_NVT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_RLOGIN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_RSH AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_TELNET AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_MODBUS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_MPLS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_MQTT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_MYSQL AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_NCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_NCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_NETBIOSSSN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_NETBIOSSSN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_NFLOG AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_NOVELL_802_3 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_NTLM AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_NTP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_NULL AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_PBB AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_PE AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_PIA_TCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_PIA_UDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_POP3 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_PPP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_PPPOE AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_PPPSERIAL AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_RADIUS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_RDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_RDPEUDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_RFB AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_ROOT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_NFS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_RPC AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_MOUNT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_NFS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_PORTMAPPER AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SIP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_SKIP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS_SMB AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SMB AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SMTP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SMTP_BDAT AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_SNAP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SNMP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SOCKS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_FINGER AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_LDAP_TCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_LDAP_UDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_QUIC AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SYSLOG AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SPICY_WEBSOCKET AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SSH AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_DTLS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_SSL AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTLINE AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_CONTENTS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_TCPSTATS AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_TCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_TCP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_TEREDO AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_UDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_UDP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_VLAN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_VNTAG AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::PACKETANALYZER_ANALYZER_VXLAN AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_WEBSOCKET AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_OCSP_REPLY AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_OCSP_REQUEST AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::FILES_ANALYZER_X509 AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_XMPP AllAnalyzers::Tag

      .. zeek:enum:: AllAnalyzers::ANALYZER_ANALYZER_ZIP AllAnalyzers::Tag

.. _plugin-zeek-bittorrent:

Zeek::BitTorrent
----------------

BitTorrent Analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_BITTORRENT`

:zeek:enum:`Analyzer::ANALYZER_BITTORRENTTRACKER`

Events
++++++

.. zeek:id:: bittorrent_peer_handshake
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 14 14

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, reserved: :zeek:type:`string`, info_hash: :zeek:type:`string`, peer_id: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_have bittorrent_peer_interested bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_keep_alive
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 27 27

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_choke
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 40 40

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_unchoke
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 53 53

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request
      bittorrent_peer_unknown bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_interested
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 66 66

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_not_interested
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 79 79

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive  bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_have
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, piece_index: :zeek:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake  bittorrent_peer_interested bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_bitfield
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 105 105

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, bitfield: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see::  bittorrent_peer_cancel bittorrent_peer_choke bittorrent_peer_handshake
      bittorrent_peer_have bittorrent_peer_interested bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_request
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 118 118

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, index: :zeek:type:`count`, begin: :zeek:type:`count`, length: :zeek:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port  bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_piece
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 131 131

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, index: :zeek:type:`count`, begin: :zeek:type:`count`, piece_length: :zeek:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_cancel
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 144 144

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, index: :zeek:type:`count`, begin: :zeek:type:`count`, length: :zeek:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield  bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_port
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 157 157

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, listen_port: :zeek:type:`port`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_unknown
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 170 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, message_id: :zeek:type:`count`, data: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_weird

.. zeek:id:: bittorrent_peer_weird
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 183 183

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown

.. zeek:id:: bt_tracker_request
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 196 196

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, uri: :zeek:type:`string`, headers: :zeek:type:`bt_tracker_headers`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. zeek:id:: bt_tracker_response
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 209 209

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, status: :zeek:type:`count`, headers: :zeek:type:`bt_tracker_headers`, peers: :zeek:type:`bittorrent_peer_set`, benc: :zeek:type:`bittorrent_benc_dir`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. zeek:id:: bt_tracker_response_not_ok
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 222 222

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, status: :zeek:type:`count`, headers: :zeek:type:`bt_tracker_headers`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. zeek:id:: bt_tracker_weird
   :source-code: base/bif/plugins/Zeek_BitTorrent.events.bif.zeek 235 235

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. zeek:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. _plugin-zeek-connsize:

Zeek::ConnSize
--------------

Connection size analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONNSIZE`

Events
++++++

.. zeek:id:: conn_bytes_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 320 337

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set byte threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   :zeek:see:`ConnThreshold::bytes_threshold_crossed` instead.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold conn_duration_threshold_crossed
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: conn_packets_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 339 356

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set packet threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   :zeek:see:`ConnThreshold::packets_threshold_crossed` instead.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold conn_duration_threshold_crossed
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: conn_duration_threshold_crossed
   :source-code: base/protocols/conn/thresholds.zeek 358 370

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, threshold: :zeek:type:`interval`, is_orig: :zeek:type:`bool`)

   Generated for a connection that crossed a set duration threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   :zeek:see:`ConnThreshold::duration_threshold_crossed` instead.
   
   Note that this event is not raised at the exact moment that a duration threshold is crossed; instead
   it is raised when the next packet is seen after the threshold has been crossed. On a connection that is
   idle, this can be raised significantly later.
   

   :param c: the connection
   

   :param threshold: the threshold that was set
   

   :param is_orig: true if the threshold was crossed by the originator of the connection
   
   .. zeek:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

Functions
+++++++++

.. zeek:id:: set_current_conn_bytes_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 19 19

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets the current byte threshold for connection sizes, overwriting any potential old
   threshold. Be aware that in nearly any case you will want to use the high level API
   instead (:zeek:see:`ConnThreshold::set_bytes_threshold`).
   

   :param cid: The connection id.
   

   :param threshold: Threshold in bytes.
   

   :param is_orig: If true, threshold is set for bytes from originator, otherwise for bytes from responder.
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: set_current_conn_packets_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 35 35

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, threshold: :zeek:type:`count`, is_orig: :zeek:type:`bool`) : :zeek:type:`bool`

   Sets a threshold for connection packets, overwriting any potential old thresholds.
   Be aware that in nearly any case you will want to use the high level API
   instead (:zeek:see:`ConnThreshold::set_packets_threshold`).
   

   :param cid: The connection id.
   

   :param threshold: Threshold in packets.
   

   :param is_orig: If true, threshold is set for packets from originator, otherwise for packets from responder.
   
   .. zeek:see:: set_current_conn_bytes_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: set_current_conn_duration_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 49 49

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, threshold: :zeek:type:`interval`) : :zeek:type:`bool`

   Sets the current duration threshold for connection, overwriting any potential old
   threshold. Be aware that in nearly any case you will want to use the high level API
   instead (:zeek:see:`ConnThreshold::set_duration_threshold`).
   

   :param cid: The connection id.
   

   :param threshold: Threshold in seconds.
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold get_current_conn_packets_threshold
                 get_current_conn_duration_threshold

.. zeek:id:: get_current_conn_bytes_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 63 63

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, is_orig: :zeek:type:`bool`) : :zeek:type:`count`

   

   :param cid: The connection id.
   

   :param is_orig: If true, threshold of originator, otherwise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in bytes
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_packets_threshold set_current_conn_duration_threshold
                 get_current_conn_duration_threshold

.. zeek:id:: get_current_conn_packets_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 76 76

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, is_orig: :zeek:type:`bool`) : :zeek:type:`count`

   Gets the current packet threshold size for a connection.
   

   :param cid: The connection id.
   

   :param is_orig: If true, threshold of originator, otherwise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in packets
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_bytes_threshold set_current_conn_duration_threshold get_current_conn_duration_threshold

.. zeek:id:: get_current_conn_duration_threshold
   :source-code: base/bif/plugins/Zeek_ConnSize.functions.bif.zeek 87 87

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`interval`

   Gets the current duration threshold size for a connection.
   

   :param cid: The connection id.
   

   :returns: 0 if no threshold is set or the threshold in seconds
   
   .. zeek:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                 get_current_conn_packets_threshold set_current_conn_duration_threshold

.. _plugin-zeek-dce-rpc:

Zeek::DCE_RPC
-------------

DCE-RPC analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_DCE_RPC`

Options/Constants
+++++++++++++++++

.. zeek:id:: DCE_RPC::max_cmd_reassembly
   :source-code: base/init-bare.zeek 5460 5460

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``20``

   The maximum number of simultaneous fragmented commands that
   the DCE_RPC analyzer will tolerate before the it will generate
   a weird and skip further input.

.. zeek:id:: DCE_RPC::max_frag_data
   :source-code: base/init-bare.zeek 5465 5465

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``30000``

   The maximum number of fragmented bytes that the DCE_RPC analyzer
   will tolerate on a command before the analyzer will generate a weird
   and skip further input.

Types
+++++

.. zeek:type:: DCE_RPC::PType
   :source-code: base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek 8 8

   :Type: :zeek:type:`enum`

      .. zeek:enum:: DCE_RPC::REQUEST DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::PING DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::RESPONSE DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::FAULT DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::WORKING DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::NOCALL DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::REJECT DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::CL_CANCEL DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::FACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::CANCEL_ACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::BIND DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::BIND_ACK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::BIND_NAK DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ALTER_CONTEXT DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ALTER_CONTEXT_RESP DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::AUTH3 DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::SHUTDOWN DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::CO_CANCEL DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::ORPHANED DCE_RPC::PType

      .. zeek:enum:: DCE_RPC::RTS DCE_RPC::PType


.. zeek:type:: DCE_RPC::IfID
   :source-code: base/bif/plugins/Zeek_DCE_RPC.types.bif.zeek 33 33

   :Type: :zeek:type:`enum`

      .. zeek:enum:: DCE_RPC::unknown_if DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::epmapper DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::lsarpc DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::lsa_ds DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::mgmt DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::netlogon DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::samr DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::srvsvc DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::spoolss DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::drs DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::winspipe DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::wkssvc DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::oxid DCE_RPC::IfID

      .. zeek:enum:: DCE_RPC::ISCMActivator DCE_RPC::IfID


Events
++++++

.. zeek:id:: dce_rpc_message
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, fid: :zeek:type:`count`, ptype_id: :zeek:type:`count`, ptype: :zeek:type:`DCE_RPC::PType`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
   

   :param c: The connection.
   

   :param is_orig: True if the message was sent by the originator of the TCP connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ptype_id: Numeric representation of the procedure type of the message.
   

   :param ptype: Enum representation of the procedure type of the message.
   
   .. zeek:see:: dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_bind
   :source-code: base/protocols/dce-rpc/main.zeek 111 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, uuid: :zeek:type:`string`, ver_major: :zeek:type:`count`, ver_minor: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param uuid: The string interpreted uuid of the endpoint being requested.
   

   :param ver_major: The major version of the endpoint being requested.
   

   :param ver_minor: The minor version of the endpoint being requested.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_alter_context
   :source-code: base/protocols/dce-rpc/main.zeek 125 137

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, uuid: :zeek:type:`string`, ver_major: :zeek:type:`count`, ver_minor: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param uuid: The string interpreted uuid of the endpoint being requested.
   

   :param ver_major: The major version of the endpoint being requested.
   

   :param ver_minor: The minor version of the endpoint being requested.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context_resp

.. zeek:id:: dce_rpc_bind_ack
   :source-code: base/protocols/dce-rpc/main.zeek 139 148

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, sec_addr: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param sec_addr: Secondary address for the ack.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_request dce_rpc_response

.. zeek:id:: dce_rpc_alter_context_resp
   :source-code: base/protocols/dce-rpc/main.zeek 150 153

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context

.. zeek:id:: dce_rpc_request
   :source-code: base/protocols/dce-rpc/main.zeek 155 163

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub_len: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param opnum: Number of the RPC operation.
   

   :param stub_len: Length of the data for the request.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response dce_rpc_request_stub

.. zeek:id:: dce_rpc_response
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 125 125

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub_len: :zeek:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.

   :param opnum: Number of the RPC operation.
   

   :param stub_len: Length of the data for the response.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response_stub

.. zeek:id:: dce_rpc_request_stub
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 143 143

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.
   

   :param opnum: Number of the RPC operation.
   

   :param stub: The data for the request.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response_stub dce_rpc_request

.. zeek:id:: dce_rpc_response_stub
   :source-code: base/bif/plugins/Zeek_DCE_RPC.events.bif.zeek 161 161

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, fid: :zeek:type:`count`, ctx_id: :zeek:type:`count`, opnum: :zeek:type:`count`, stub: :zeek:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :param c: The connection.
   

   :param fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :param ctx_id: The context identifier of the data representation.

   :param opnum: Number of the RPC operation.
   

   :param stub: The data for the response.
   
   .. zeek:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request_stub dce_rpc_response

.. _plugin-zeek-dhcp:

Zeek::DHCP
----------

DHCP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_DHCP`

Types
+++++

.. zeek:type:: DHCP::Msg
   :source-code: base/init-bare.zeek 3886 3901

   :Type: :zeek:type:`record`

      op: :zeek:type:`count`
         Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY

      m_type: :zeek:type:`count`
         The type of DHCP message.

      xid: :zeek:type:`count`
         Transaction ID of a DHCP session.

      secs: :zeek:type:`interval`
         Number of seconds since client began address acquisition
         or renewal process

      flags: :zeek:type:`count`

      ciaddr: :zeek:type:`addr`
         Original IP address of the client.

      yiaddr: :zeek:type:`addr`
         IP address assigned to the client.

      siaddr: :zeek:type:`addr`
         IP address of the server.

      giaddr: :zeek:type:`addr`
         IP address of the relaying gateway.

      chaddr: :zeek:type:`string`
         Client hardware address.

      sname: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Server host name.

      file_n: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`
         Boot file name.

   A DHCP message.
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::Addrs
   :source-code: base/init-bare.zeek 3882 3882

   :Type: :zeek:type:`vector` of :zeek:type:`addr`

   A list of addresses offered by a DHCP server.  Could be routers,
   DNS servers, or other.
   
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::SubOpt
   :source-code: base/init-bare.zeek 3925 3928

   :Type: :zeek:type:`record`

      code: :zeek:type:`count`

      value: :zeek:type:`string`

   DHCP Relay Agent Information Option (Option 82)
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::SubOpts
   :source-code: base/init-bare.zeek 3930 3930

   :Type: :zeek:type:`vector` of :zeek:type:`DHCP::SubOpt`


.. zeek:type:: DHCP::ClientFQDN
   :source-code: base/init-bare.zeek 3911 3921

   :Type: :zeek:type:`record`

      flags: :zeek:type:`count`
         An unparsed bitfield of flags (refer to RFC 4702).

      rcode1: :zeek:type:`count`
         This field is deprecated in the standard.

      rcode2: :zeek:type:`count`
         This field is deprecated in the standard.

      domain_name: :zeek:type:`string`
         The Domain Name part of the option carries all or part of the FQDN
         of a DHCP client.

   DHCP Client FQDN Option information (Option 81)

.. zeek:type:: DHCP::ClientID
   :source-code: base/init-bare.zeek 3905 3908

   :Type: :zeek:type:`record`

      hwtype: :zeek:type:`count`

      hwaddr: :zeek:type:`string`

   DHCP Client Identifier (Option 61)
   .. zeek:see:: dhcp_message

.. zeek:type:: DHCP::Options
   :source-code: base/init-bare.zeek 3932 4030

   :Type: :zeek:type:`record`

      options: :zeek:type:`index_vec` :zeek:attr:`&optional`
         The ordered list of all DHCP option numbers.

      subnet_mask: :zeek:type:`addr` :zeek:attr:`&optional`
         Subnet Mask Value (option 1)

      routers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         Router addresses (option 3)

      dns_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         DNS Server addresses (option 6)

      host_name: :zeek:type:`string` :zeek:attr:`&optional`
         The Hostname of the client (option 12)

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The DNS domain name of the client (option 15)

      forwarding: :zeek:type:`bool` :zeek:attr:`&optional`
         Enable/Disable IP Forwarding (option 19)

      broadcast: :zeek:type:`addr` :zeek:attr:`&optional`
         Broadcast Address (option 28)

      vendor: :zeek:type:`string` :zeek:attr:`&optional`
         Vendor specific data. This can frequently
         be unparsed binary data. (option 43)

      nbns: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         NETBIOS name server list (option 44)

      addr_request: :zeek:type:`addr` :zeek:attr:`&optional`
         Address requested by the client (option 50)

      lease: :zeek:type:`interval` :zeek:attr:`&optional`
         Lease time offered by the server. (option 51)

      serv_addr: :zeek:type:`addr` :zeek:attr:`&optional`
         Server address to allow clients to distinguish
         between lease offers. (option 54)

      param_list: :zeek:type:`index_vec` :zeek:attr:`&optional`
         DHCP Parameter Request list (option 55)

      message: :zeek:type:`string` :zeek:attr:`&optional`
         Textual error message (option 56)

      max_msg_size: :zeek:type:`count` :zeek:attr:`&optional`
         Maximum Message Size (option 57)

      renewal_time: :zeek:type:`interval` :zeek:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         RENEWING state. (option 58)

      rebinding_time: :zeek:type:`interval` :zeek:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         REBINDING state. (option 59)

      vendor_class: :zeek:type:`string` :zeek:attr:`&optional`
         This option is used by DHCP clients to optionally
         identify the vendor type and configuration of a DHCP
         client. (option 60)

      client_id: :zeek:type:`DHCP::ClientID` :zeek:attr:`&optional`
         DHCP Client Identifier (Option 61)

      user_class: :zeek:type:`string` :zeek:attr:`&optional`
         User Class opaque value (Option 77)

      client_fqdn: :zeek:type:`DHCP::ClientFQDN` :zeek:attr:`&optional`
         DHCP Client FQDN (Option 81)

      sub_opt: :zeek:type:`DHCP::SubOpts` :zeek:attr:`&optional`
         DHCP Relay Agent Information Option (Option 82)

      auto_config: :zeek:type:`bool` :zeek:attr:`&optional`
         Auto Config option to let host know if it's allowed to
         auto assign an IP address. (Option 116)

      auto_proxy_config: :zeek:type:`string` :zeek:attr:`&optional`
         URL to find a proxy.pac for auto proxy config (Option 252)

      time_offset: :zeek:type:`int` :zeek:attr:`&optional`
         The offset of the client's subnet in seconds from UTC. (Option 2)

      time_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         A list of :rfc:`868` time servers available to the client.
         (Option 4)

      name_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         A list of IEN 116 name servers available to the client. (Option 5)

      ntp_servers: :zeek:type:`DHCP::Addrs` :zeek:attr:`&optional`
         A list of IP addresses indicating NTP servers available to the
         client. (Option 42)


Events
++++++

.. zeek:id:: dhcp_message
   :source-code: base/protocols/dhcp/main.zeek 308 311

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`DHCP::Msg`, options: :zeek:type:`DHCP::Options`)

   Generated for all DHCP messages.
   

   :param c: The connection record describing the underlying UDP flow.
   

   :param is_orig: Indicate if the message came in a packet from the
           originator/client of the udp flow or the responder/server.
   

   :param msg: The parsed type-independent part of the DHCP message. The message
        type is indicated in this record.
   

   :param options: The full set of supported and parsed DHCP options.

.. _plugin-zeek-dnp3:

Zeek::DNP3
----------

DNP3 UDP/TCP analyzers

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_DNP3_TCP`

:zeek:enum:`Analyzer::ANALYZER_DNP3_UDP`

Events
++++++

.. zeek:id:: dnp3_application_request_header
   :source-code: base/protocols/dnp3/main.zeek 49 59

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, application: :zeek:type:`count`, fc: :zeek:type:`count`)

   Generated for a DNP3 request header.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param fc: function code.
   

.. zeek:id:: dnp3_application_response_header
   :source-code: base/protocols/dnp3/main.zeek 61 76

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, application: :zeek:type:`count`, fc: :zeek:type:`count`, iin: :zeek:type:`count`)

   Generated for a DNP3 response header.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param fc: function code.
   

   :param iin: internal indication number.
   

.. zeek:id:: dnp3_object_header
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 50 50

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, obj_type: :zeek:type:`count`, qua_field: :zeek:type:`count`, number: :zeek:type:`count`, rf_low: :zeek:type:`count`, rf_high: :zeek:type:`count`)

   Generated for the object header found in both DNP3 requests and responses.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param obj_type: type of object, which is classified based on an 8-bit group number
             and an 8-bit variation number.
   

   :param qua_field: qualifier field.
   

   :param number: TODO.
   

   :param rf_low: the structure of the range field depends on the qualified field.
           In some cases, the range field contains only one logic part, e.g.,
           number of objects, so only *rf_low* contains useful values.
   

   :param rf_high: in some cases, the range field contains two logic parts, e.g., start
            index and stop index, so *rf_low* contains the start index
            while *rf_high* contains the stop index.
   

.. zeek:id:: dnp3_object_prefix
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 62 62

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix_value: :zeek:type:`count`)

   Generated for the prefix before a DNP3 object. The structure and the meaning
   of the prefix are defined by the qualifier field.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param prefix_value: The prefix.
   

.. zeek:id:: dnp3_header_block
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 82 82

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, len: :zeek:type:`count`, ctrl: :zeek:type:`count`, dest_addr: :zeek:type:`count`, src_addr: :zeek:type:`count`)

   Generated for an additional header that the DNP3 analyzer passes to the
   script-level. This header mimics the DNP3 transport-layer yet is only passed
   once for each sequence of DNP3 records (which are otherwise reassembled and
   treated as a single entity).
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param len:   the "length" field in the DNP3 Pseudo Link Layer.
   

   :param ctrl:  the "control" field in the DNP3 Pseudo Link Layer.
   

   :param dest_addr: the "destination" field in the DNP3 Pseudo Link Layer.
   

   :param src_addr: the "source" field in the DNP3 Pseudo Link Layer.
   

.. zeek:id:: dnp3_response_data_object
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 99 99

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data_value: :zeek:type:`count`)

   Generated for a DNP3 "Response_Data_Object".
   The "Response_Data_Object" contains two parts: object prefix and object
   data. In most cases, object data are defined by new record types. But
   in a few cases, object data are directly basic types, such as int16_t, or
   int8_t; thus we use an additional *data_value* to record the values of those
   object data.
   

   :param c: The connection the DNP3 communication is part of.
   

   :param is_orig: True if this reflects originator-side activity.
   

   :param data_value: The value for those objects that carry their information here
               directly.
   

.. zeek:id:: dnp3_attribute_common
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 103 103

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data_type_code: :zeek:type:`count`, leng: :zeek:type:`count`, attribute_obj: :zeek:type:`string`)

   Generated for DNP3 attributes.

.. zeek:id:: dnp3_crob
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 108 108

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, control_code: :zeek:type:`count`, count8: :zeek:type:`count`, on_time: :zeek:type:`count`, off_time: :zeek:type:`count`, status_code: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 1

   :param CROB: control relay output block

.. zeek:id:: dnp3_pcb
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 113 113

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, control_code: :zeek:type:`count`, count8: :zeek:type:`count`, on_time: :zeek:type:`count`, off_time: :zeek:type:`count`, status_code: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 2

   :param PCB: Pattern Control Block

.. zeek:id:: dnp3_counter_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 118 118

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 1
   counter 32 bit with flag

.. zeek:id:: dnp3_counter_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 123 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 2
   counter 16 bit with flag

.. zeek:id:: dnp3_counter_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 128 128

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 5
   counter 32 bit without flag

.. zeek:id:: dnp3_counter_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 133 133

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 6
   counter 16 bit without flag

.. zeek:id:: dnp3_frozen_counter_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 138 138

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 1
   frozen counter 32 bit with flag

.. zeek:id:: dnp3_frozen_counter_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 143 143

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 2
   frozen counter 16 bit with flag

.. zeek:id:: dnp3_frozen_counter_32wFlagTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 148 148

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 5
   frozen counter 32 bit with flag and time

.. zeek:id:: dnp3_frozen_counter_16wFlagTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 153 153

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, count_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 6
   frozen counter 16 bit with flag and time

.. zeek:id:: dnp3_frozen_counter_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 158 158

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 9
   frozen counter 32 bit without flag

.. zeek:id:: dnp3_frozen_counter_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 163 163

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, count_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 10
   frozen counter 16 bit without flag

.. zeek:id:: dnp3_analog_input_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 168 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 1
   analog input 32 bit with flag

.. zeek:id:: dnp3_analog_input_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 173 173

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 2
   analog input 16 bit with flag

.. zeek:id:: dnp3_analog_input_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 178 178

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 3
   analog input 32 bit without flag

.. zeek:id:: dnp3_analog_input_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 183 183

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 4
   analog input 16 bit without flag

.. zeek:id:: dnp3_analog_input_SPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 188 188

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 5
   analog input single precision, float point with flag

.. zeek:id:: dnp3_analog_input_DPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 193 193

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 6
   analog input double precision, float point with flag

.. zeek:id:: dnp3_frozen_analog_input_32wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 198 198

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 1
   frozen analog input 32 bit with flag

.. zeek:id:: dnp3_frozen_analog_input_16wFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 203 203

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 2
   frozen analog input 16 bit with flag

.. zeek:id:: dnp3_frozen_analog_input_32wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 208 208

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 3
   frozen analog input 32 bit with time-of-freeze

.. zeek:id:: dnp3_frozen_analog_input_16wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 213 213

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 4
   frozen analog input 16 bit with time-of-freeze

.. zeek:id:: dnp3_frozen_analog_input_32woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 218 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 5
   frozen analog input 32 bit without flag

.. zeek:id:: dnp3_frozen_analog_input_16woFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 223 223

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 6
   frozen analog input 16 bit without flag

.. zeek:id:: dnp3_frozen_analog_input_SPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 228 228

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 7
   frozen analog input single-precision, float point with flag

.. zeek:id:: dnp3_frozen_analog_input_DPwFlag
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 233 233

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 8
   frozen analog input double-precision, float point with flag

.. zeek:id:: dnp3_analog_input_event_32woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 238 238

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 1
   analog input event 32 bit without time

.. zeek:id:: dnp3_analog_input_event_16woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 243 243

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 2
   analog input event 16 bit without time

.. zeek:id:: dnp3_analog_input_event_32wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 248 248

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 3
   analog input event 32 bit with time

.. zeek:id:: dnp3_analog_input_event_16wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 4
   analog input event 16 bit with time

.. zeek:id:: dnp3_analog_input_event_SPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 258 258

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 5
   analog input event single-precision float point without time

.. zeek:id:: dnp3_analog_input_event_DPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 263 263

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 6
   analog input event double-precision float point without time

.. zeek:id:: dnp3_analog_input_event_SPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 268 268

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 7
   analog input event single-precision float point with time

.. zeek:id:: dnp3_analog_input_event_DPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 273 273

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, value_low: :zeek:type:`count`, value_high: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 8
   analog input event double-precision float point with time

.. zeek:id:: dnp3_frozen_analog_input_event_32woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 278 278

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 1
   frozen analog input event 32 bit without time

.. zeek:id:: dnp3_frozen_analog_input_event_16woTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 283 283

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 2
   frozen analog input event 16 bit without time

.. zeek:id:: dnp3_frozen_analog_input_event_32wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 288 288

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 3
   frozen analog input event 32 bit with time

.. zeek:id:: dnp3_frozen_analog_input_event_16wTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 293 293

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 4
   frozen analog input event 16 bit with time

.. zeek:id:: dnp3_frozen_analog_input_event_SPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 298 298

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 5
   frozen analog input event single-precision float point without time

.. zeek:id:: dnp3_frozen_analog_input_event_DPwoTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 303 303

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 6
   frozen analog input event double-precision float point without time

.. zeek:id:: dnp3_frozen_analog_input_event_SPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 308 308

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 7
   frozen analog input event single-precision float point with time

.. zeek:id:: dnp3_frozen_analog_input_event_DPwTime
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 313 313

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flag: :zeek:type:`count`, frozen_value_low: :zeek:type:`count`, frozen_value_high: :zeek:type:`count`, time48: :zeek:type:`count`)

   Generated for DNP3 objects with the group number 34 and variation number 8
   frozen analog input event double-precision float point with time

.. zeek:id:: dnp3_file_transport
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 317 317

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, file_handle: :zeek:type:`count`, block_num: :zeek:type:`count`, file_data: :zeek:type:`string`)

   g70

.. zeek:id:: dnp3_debug_byte
   :source-code: base/bif/plugins/Zeek_DNP3.events.bif.zeek 323 323

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, debug: :zeek:type:`string`)

   Debugging event generated by the DNP3 analyzer. The "Debug_Byte" binpac unit
   generates this for unknown "cases". The user can use it to debug the byte
   string to check what caused the malformed network packets.

.. _plugin-zeek-dns:

Zeek::DNS
---------

DNS analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_DNS`

:zeek:enum:`Analyzer::ANALYZER_DNS`

Events
++++++

.. zeek:id:: dns_message
   :source-code: base/protocols/dns/main.zeek 348 355

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`dns_msg`, len: :zeek:type:`count`)

   Generated for all DNS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param is_orig:  True if the message was sent by the originator of the connection.
   

   :param msg: The parsed DNS message header.
   

   :param len: The length of the message's raw representation (i.e., the DNS payload).
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid  dns_query_reply dns_rejected
      dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_request
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`, original_query: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for DNS requests. For requests with multiple queries, this event
   is raised once for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param query: The queried name (normalized to all lowercase).
   

   :param qtype: The queried resource record type.
   

   :param qclass: The queried resource record class.
   

   :param original_query: The queried name, with the original case kept intact
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_rejected
   :source-code: base/protocols/dns/main.zeek 616 620

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`, original_query: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for DNS replies that reject a query. This event is raised if a DNS
   reply indicates failure because it does not pass on any
   answers to a query. Note that all of the event's parameters are parsed out of
   the reply; there's no stateful correlation with the query.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param query: The queried name (normalized to all lowercase).
   

   :param qtype: The queried resource record type.
   

   :param qclass: The queried resource record class.
   

   :param original_query: The queried name, with the original case kept intact
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_query_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 121 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`, original_query: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, query: :zeek:type:`string`, qtype: :zeek:type:`count`, qclass: :zeek:type:`count`)

   Generated for each entry in the Question section of a DNS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param query: The queried name.
   

   :param qtype: The queried resource record type.
   

   :param qclass: The queried resource record class.
   

   :param original_query: The queried name, with the original case kept intact
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_rejected
      dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_A_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 149 149

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *A*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param a: The address returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_AAAA_reply
   :source-code: base/protocols/dns/main.zeek 494 497

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *AAAA*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param a: The address returned by the reply.
   
   .. zeek:see::  dns_A_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_A6_reply
   :source-code: base/protocols/dns/main.zeek 499 502

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, a: :zeek:type:`addr`)

   Generated for DNS replies of type *A6*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param a: The address returned by the reply.
   
   .. zeek:see::  dns_A_reply dns_AAAA_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_NS_reply
   :source-code: base/protocols/dns/main.zeek 504 507

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *NS*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply  dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_CNAME_reply
   :source-code: base/protocols/dns/main.zeek 509 512

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply  dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_PTR_reply
   :source-code: base/protocols/dns/main.zeek 520 523

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`)

   Generated for DNS replies of type *PTR*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply  dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_SOA_reply
   :source-code: base/protocols/dns/main.zeek 525 528

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, soa: :zeek:type:`dns_soa`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param soa: The parsed SOA value.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_WKS_reply
   :source-code: base/protocols/dns/main.zeek 530 533

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated for DNS replies of type *WKS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply  dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_HINFO_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 353 353

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, cpu: :zeek:type:`string`, os: :zeek:type:`string`)

   Generated for DNS replies of type *HINFO*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_MX_reply
   :source-code: base/protocols/dns/main.zeek 515 518

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, name: :zeek:type:`string`, preference: :zeek:type:`count`)

   Generated for DNS replies of type *MX*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param name: The name returned by the reply.
   

   :param preference: The preference for *name* specified by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply  dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_TXT_reply
   :source-code: base/protocols/dns/main.zeek 464 477

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, strs: :zeek:type:`string_vec`)

   Generated for DNS replies of type *TXT*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param strs: The textual information returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_SPF_reply
   :source-code: base/protocols/dns/main.zeek 479 492

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, strs: :zeek:type:`string_vec`)

   Generated for DNS replies of type *SPF*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param strs: The textual information returned by the reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_CAA_reply
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 453 453

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, flags: :zeek:type:`count`, tag: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for DNS replies of type *CAA* (Certification Authority Authorization).
   For replies with multiple answers, an individual event of the corresponding type
   is raised for each.
   See `RFC 6844 <https://tools.ietf.org/html/rfc6844>`__ for more details.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param flags: The flags byte of the CAA reply.
   

   :param tag: The property identifier of the CAA reply.
   

   :param value: The property value of the CAA reply.

.. zeek:id:: dns_SRV_reply
   :source-code: base/protocols/dns/main.zeek 535 538

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, target: :zeek:type:`string`, priority: :zeek:type:`count`, weight: :zeek:type:`count`, p: :zeek:type:`count`)

   Generated for DNS replies of type *SRV*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param target: Target of the SRV response -- the canonical hostname of the
           machine providing the service, ending in a dot.
   

   :param priority: Priority of the SRV response -- the priority of the target
             host, lower value means more preferred.
   

   :param weight: Weight of the SRV response -- a relative weight for records
           with the same priority, higher value means more preferred.
   

   :param p: Port of the SRV response -- the TCP or UDP port on which the
      service is to be found.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_unknown_reply
   :source-code: base/protocols/dns/main.zeek 454 457

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`)

   Generated on DNS reply resource records when the type of record is not one
   that Zeek knows how to parse and generate another more specific event.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_SRV_reply dns_end

.. zeek:id:: dns_EDNS_addl
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 529 529

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_edns_additional`)

   Generated for DNS replies of type *EDNS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The parsed EDNS reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_EDNS_ecs
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 553 553

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, opt: :zeek:type:`dns_edns_ecs`)

   Generated for DNS replies of type *EDNS*. For replies with multiple options,
   an individual event is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param opt: The parsed EDNS option.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_EDNS_tcp_keepalive
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 579 579

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, opt: :zeek:type:`dns_edns_tcp_keepalive`)

   Generated for DNS replies of type *EDNS*, and an option field in this *EDNS* record has
   an opt-type of 11. For replies with multiple option fields, an individual event is
   raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. See `RFC7828 <https://tools.ietf.org/html/rfc7828>`__ for
   more information about EDNS0 TCP keepalive. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param opt: The parsed EDNS Keepalive option.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_EDNS_cookie
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 605 605

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, opt: :zeek:type:`dns_edns_cookie`)

   Generated for DNS replies of type *EDNS*, and an option field in this *EDNS* record has
   an opt-type of 10. For replies with multiple options fields, an individual event
   is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. See `RFC7873 <https://tools.ietf.org/html/rfc7873>`__ for
   more information about EDNS0 cookie. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param opt: The parsed EDNS Cookie option.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_TSIG_addl
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 629 629

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_tsig_additional`)

   Generated for DNS replies of type *TSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The parsed TSIG reply.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply  dns_TXT_reply dns_SPF_reply dns_WKS_reply dns_end
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. zeek:id:: dns_RRSIG
   :source-code: base/protocols/dns/main.zeek 560 566

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, rrsig: :zeek:type:`dns_rrsig_rr`)

   Generated for DNS replies of type *RRSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param rrsig: The parsed RRSIG record.

.. zeek:id:: dns_DNSKEY
   :source-code: base/protocols/dns/main.zeek 568 573

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, dnskey: :zeek:type:`dns_dnskey_rr`)

   Generated for DNS replies of type *DNSKEY*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param dnskey: The parsed DNSKEY record.

.. zeek:id:: dns_NSEC
   :source-code: base/protocols/dns/main.zeek 575 578

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, next_name: :zeek:type:`string`, bitmaps: :zeek:type:`string_vec`)

   Generated for DNS replies of type *NSEC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param next_name: The parsed next secure domain name.
   

   :param bitmaps: vector of strings in hex for the bit maps present.

.. zeek:id:: dns_NSEC3
   :source-code: base/protocols/dns/main.zeek 580 583

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, nsec3: :zeek:type:`dns_nsec3_rr`)

   Generated for DNS replies of type *NSEC3*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param nsec3: The parsed RDATA of Nsec3 record.

.. zeek:id:: dns_NSEC3PARAM
   :source-code: base/protocols/dns/main.zeek 585 588

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, nsec3param: :zeek:type:`dns_nsec3param_rr`)

   Generated for DNS replies of type *NSEC3PARAM*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param nsec3param: The parsed RDATA of NSEC3PARAM record.

.. zeek:id:: dns_DS
   :source-code: base/protocols/dns/main.zeek 590 595

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, ds: :zeek:type:`dns_ds_rr`)

   Generated for DNS replies of type *DS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param ds: The parsed RDATA of DS record.

.. zeek:id:: dns_BINDS
   :source-code: base/protocols/dns/main.zeek 597 600

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, binds: :zeek:type:`dns_binds_rr`)

   Generated for DNS replies of type *BINDS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param binds: The parsed RDATA of BIND-Signing state record.

.. zeek:id:: dns_SSHFP
   :source-code: base/protocols/dns/main.zeek 602 607

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, algo: :zeek:type:`count`, fptype: :zeek:type:`count`, fingerprint: :zeek:type:`string`)

   Generated for DNS replies of type *BINDS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param binds: The parsed RDATA of BIND-Signing state record.

.. zeek:id:: dns_LOC
   :source-code: base/protocols/dns/main.zeek 609 614

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, loc: :zeek:type:`dns_loc_rr`)

   Generated for DNS replies of type *LOC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param loc: The parsed RDATA of LOC type record.

.. zeek:id:: dns_SVCB
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 773 773

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, svcb: :zeek:type:`dns_svcb_rr`)

   Generated for DNS replies of type *SVCB* (General Purpose Service Endpoints).
   See `RFC draft for DNS SVCB/HTTPS <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-07>`__
   for more information about DNS SVCB/HTTPS resource records.
   For replies with multiple answers, an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param svcb: The parsed RDATA of SVCB type record.

.. zeek:id:: dns_HTTPS
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 790 790

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`, ans: :zeek:type:`dns_answer`, https: :zeek:type:`dns_svcb_rr`)

   Generated for DNS replies of type *HTTPS* (HTTPS Specific Service Endpoints).
   See `RFC draft for DNS SVCB/HTTPS <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-svcb-https-07>`__
   for more information about DNS SVCB/HTTPS resource records.
   Since SVCB and HTTPS records share the same wire format layout, the argument https is dns_svcb_rr.
   For replies with multiple answers, an individual event of the corresponding type is raised for each.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   

   :param ans: The type-independent part of the parsed answer record.
   

   :param https: The parsed RDATA of HTTPS type record.

.. zeek:id:: dns_end
   :source-code: base/bif/plugins/Zeek_DNS.events.bif.zeek 813 813

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`dns_msg`)

   Generated at the end of processing a DNS packet. This event is the last
   ``dns_*`` event that will be raised for a DNS query/reply and signals that
   all resource records have been passed on.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Zeek analyzes both UDP and TCP DNS
   sessions.
   

   :param c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :param msg: The parsed DNS message header.
   
   .. zeek:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_SPF_reply dns_WKS_reply
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. _plugin-zeek-file:

Zeek::File
----------

Generic file analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_FTP_DATA`

Events
++++++

.. zeek:id:: file_transferred
   :source-code: base/protocols/ftp/main.zeek 445 453

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, prefix: :zeek:type:`string`, descr: :zeek:type:`string`, mime_type: :zeek:type:`string`)

   Generated when a TCP connection associated w/ file data transfer is seen
   (e.g. as happens w/ FTP or IRC).
   

   :param c: The connection over which file data is transferred.
   

   :param prefix: Up to 1024 bytes of the file data.
   

   :param descr: Deprecated/unused argument.
   

   :param mime_type: MIME type of the file or "<unknown>" if no file magic signatures
              matched.

.. _plugin-zeek-finger:

Zeek::Finger
------------

Finger analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_FINGER`

Types
+++++

.. zeek:type:: spicy::AddressFamily

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::AddressFamily_IPv4 spicy::AddressFamily

      .. zeek:enum:: spicy::AddressFamily_IPv6 spicy::AddressFamily

      .. zeek:enum:: spicy::AddressFamily_Undef spicy::AddressFamily


.. zeek:type:: spicy::BitOrder

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::BitOrder_LSB0 spicy::BitOrder

      .. zeek:enum:: spicy::BitOrder_MSB0 spicy::BitOrder

      .. zeek:enum:: spicy::BitOrder_Undef spicy::BitOrder


.. zeek:type:: spicy::ByteOrder

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::ByteOrder_Little spicy::ByteOrder

      .. zeek:enum:: spicy::ByteOrder_Big spicy::ByteOrder

      .. zeek:enum:: spicy::ByteOrder_Network spicy::ByteOrder

      .. zeek:enum:: spicy::ByteOrder_Host spicy::ByteOrder

      .. zeek:enum:: spicy::ByteOrder_Undef spicy::ByteOrder


.. zeek:type:: spicy::Charset

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::Charset_ASCII spicy::Charset

      .. zeek:enum:: spicy::Charset_UTF8 spicy::Charset

      .. zeek:enum:: spicy::Charset_Undef spicy::Charset


.. zeek:type:: spicy::DecodeErrorStrategy

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::DecodeErrorStrategy_IGNORE spicy::DecodeErrorStrategy

      .. zeek:enum:: spicy::DecodeErrorStrategy_REPLACE spicy::DecodeErrorStrategy

      .. zeek:enum:: spicy::DecodeErrorStrategy_STRICT spicy::DecodeErrorStrategy

      .. zeek:enum:: spicy::DecodeErrorStrategy_Undef spicy::DecodeErrorStrategy


.. zeek:type:: spicy::Protocol

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::Protocol_TCP spicy::Protocol

      .. zeek:enum:: spicy::Protocol_UDP spicy::Protocol

      .. zeek:enum:: spicy::Protocol_ICMP spicy::Protocol

      .. zeek:enum:: spicy::Protocol_Undef spicy::Protocol


.. zeek:type:: spicy::RealType

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::RealType_IEEE754_Single spicy::RealType

      .. zeek:enum:: spicy::RealType_IEEE754_Double spicy::RealType

      .. zeek:enum:: spicy::RealType_Undef spicy::RealType


.. zeek:type:: spicy::ReassemblerPolicy

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::ReassemblerPolicy_First spicy::ReassemblerPolicy

      .. zeek:enum:: spicy::ReassemblerPolicy_Undef spicy::ReassemblerPolicy


.. zeek:type:: spicy::Side

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::Side_Left spicy::Side

      .. zeek:enum:: spicy::Side_Right spicy::Side

      .. zeek:enum:: spicy::Side_Both spicy::Side

      .. zeek:enum:: spicy::Side_Undef spicy::Side


.. zeek:type:: spicy::Direction

   :Type: :zeek:type:`enum`

      .. zeek:enum:: spicy::Direction_Forward spicy::Direction

      .. zeek:enum:: spicy::Direction_Backward spicy::Direction

      .. zeek:enum:: spicy::Direction_Undef spicy::Direction


Events
++++++

.. zeek:id:: finger_request
   :source-code: base/protocols/finger/spicy-events.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, full: :zeek:type:`bool`, username: :zeek:type:`string`, hostname: :zeek:type:`string`)

   Generated for Finger requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :param c: The connection.
   

   :param full: True if verbose information is requested (``/W`` switch).
   

   :param username: The request's user name.
   

   :param hostname: The request's host name.
   
   .. zeek:see:: finger_reply

.. zeek:id:: finger_reply
   :source-code: base/protocols/finger/spicy-events.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, reply_line: :zeek:type:`string`)

   Generated for Finger replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :param c: The connection.
   

   :param reply_line: The reply as returned by the server
   
   .. zeek:see:: finger_request

.. _plugin-zeek-ftp:

Zeek::FTP
---------

FTP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_FTP`

:zeek:enum:`Analyzer::ANALYZER_FTP_ADAT`

Types
+++++

.. zeek:type:: ftp_port
   :source-code: base/init-bare.zeek 352 356

   :Type: :zeek:type:`record`

      h: :zeek:type:`addr`
         The host's address.

      p: :zeek:type:`port`
         The host's port.

      valid: :zeek:type:`bool`
         True if format was right. Only then are *h* and *p* valid.

   A parsed host/port combination describing server endpoint for an upcoming
   data transfer.
   
   .. zeek:see:: fmt_ftp_port parse_eftp_port parse_ftp_epsv parse_ftp_pasv
      parse_ftp_port

Events
++++++

.. zeek:id:: ftp_request
   :source-code: base/bif/plugins/Zeek_FTP.events.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, command: :zeek:type:`string`, arg: :zeek:type:`string`)

   Generated for client-side FTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :param c: The connection.
   

   :param command: The FTP command issued by the client (without any arguments).
   

   :param arg: The arguments going with the command.
   
   .. zeek:see:: ftp_reply fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port

.. zeek:id:: ftp_reply
   :source-code: base/bif/plugins/Zeek_FTP.events.bif.zeek 38 38

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`, msg: :zeek:type:`string`, cont_resp: :zeek:type:`bool`)

   Generated for server-side FTP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :param c: The connection.
   

   :param code: The numerical response code the server responded with.
   

   :param msg:  The textual message of the response.
   

   :param cont_resp: True if the reply line is tagged as being continued to the next
              line. If so, further events will be raised and a handler may want
              to reassemble the pieces before processing the response any
              further.
   
   .. zeek:see:: ftp_request fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port

Functions
+++++++++

.. zeek:id:: parse_ftp_port
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 17 17

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts a string representation of the FTP PORT command to an
   :zeek:type:`ftp_port`.
   

   :param s: The string of the FTP PORT command, e.g., ``"10,0,0,1,4,31"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_eftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port

.. zeek:id:: parse_eftp_port
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 30 30

   :Type: :zeek:type:`function` (s: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts a string representation of the FTP EPRT command (see :rfc:`2428`)
   to an :zeek:type:`ftp_port`.  The format is
   ``"EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :param s: The string of the FTP EPRT command, e.g., ``"|1|10.0.0.1|1055|"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_ftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port

.. zeek:id:: parse_ftp_pasv
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 40 40

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts the result of the FTP PASV command to an :zeek:type:`ftp_port`.
   

   :param str: The string containing the result of the FTP PASV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_ftp_port parse_eftp_port parse_ftp_epsv fmt_ftp_port

.. zeek:id:: parse_ftp_epsv
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 52 52

   :Type: :zeek:type:`function` (str: :zeek:type:`string`) : :zeek:type:`ftp_port`

   Converts the result of the FTP EPSV command (see :rfc:`2428`) to an
   :zeek:type:`ftp_port`.  The format is ``"<text> (<d><d><d><tcp-port><d>)"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :param str: The string containing the result of the FTP EPSV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. zeek:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv fmt_ftp_port

.. zeek:id:: fmt_ftp_port
   :source-code: base/bif/plugins/Zeek_FTP.functions.bif.zeek 65 65

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, p: :zeek:type:`port`) : :zeek:type:`string`

   Formats an IP address and TCP port as an FTP PORT command. For example,
   ``10.0.0.1`` and ``1055/tcp`` yields ``"10,0,0,1,4,31"``.
   

   :param a: The IP address.
   

   :param p: The TCP port.
   

   :returns: The FTP PORT string.
   
   .. zeek:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv parse_ftp_epsv

.. _plugin-zeek-gnutella:

Zeek::Gnutella
--------------

Gnutella analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_GNUTELLA`

Events
++++++

.. zeek:id:: gnutella_text_msg
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, headers: :zeek:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see::  gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish gnutella_partial_binary_msg
   
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_binary_msg
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 32 32

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, msg_type: :zeek:type:`count`, ttl: :zeek:type:`count`, hops: :zeek:type:`count`, msg_len: :zeek:type:`count`, payload: :zeek:type:`string`, payload_len: :zeek:type:`count`, trunc: :zeek:type:`bool`, complete: :zeek:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_establish gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_partial_binary_msg
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 47 47

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, msg: :zeek:type:`string`, len: :zeek:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish  gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_establish
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 62 62

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg  gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_not_establish
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 77 77

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: gnutella_http_notify
   :source-code: base/bif/plugins/Zeek_Gnutella.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. zeek:see:: gnutella_binary_msg gnutella_establish gnutella_not_establish
      gnutella_partial_binary_msg gnutella_text_msg
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. _plugin-zeek-gssapi:

Zeek::GSSAPI
------------

GSSAPI analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_GSSAPI`

Events
++++++

.. zeek:id:: gssapi_neg_result
   :source-code: base/bif/plugins/Zeek_GSSAPI.events.bif.zeek 10 10

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, state: :zeek:type:`count`)

   Generated for GSSAPI negotiation results.
   

   :param c: The connection.
   

   :param state: The resulting state of the negotiation.
   

.. _plugin-zeek-http:

Zeek::HTTP
----------

HTTP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_HTTP`

Events
++++++

.. zeek:id:: http_request
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 26 26

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, method: :zeek:type:`string`, original_URI: :zeek:type:`string`, unescaped_URI: :zeek:type:`string`, version: :zeek:type:`string`)

   Generated for HTTP requests. Zeek supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues. This event is generated as soon as a request's initial line has
   been parsed, and before any :zeek:id:`http_header` events are raised.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param method: The HTTP method extracted from the request (e.g., ``GET``, ``POST``).
   

   :param original_URI: The unprocessed URI as specified in the request.
   

   :param unescaped_URI: The URI with all percent-encodings decoded.
   

   :param version: The version number specified in the request (e.g., ``1.1``).
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply http_stats
      truncate_http_URI http_connection_upgrade

.. zeek:id:: http_reply
   :source-code: base/protocols/http/main.zeek 265 304

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`string`, code: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated for HTTP replies. Zeek supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues. This event is generated as soon as a reply's initial line has
   been parsed, and before any :zeek:id:`http_header` events are raised.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param version: The version number specified in the reply (e.g., ``1.1``).
   

   :param code: The numerical response code returned by the server.
   

   :param reason: The textual description returned by the server along with *code*.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_request
      http_stats http_connection_upgrade

.. zeek:id:: http_header
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 74 74

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, original_name: :zeek:type:`string`, name: :zeek:type:`string`, value: :zeek:type:`string`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, name: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for HTTP headers. Zeek supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the header was sent by the originator of the TCP connection.
   

   :param original_name: The name of the header (unaltered).
   

   :param name: The name of the header (converted to all uppercase).
   

   :param value: The value of the header.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event  http_message_done http_reply http_request
      http_stats http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. zeek:id:: http_all_headers
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 100 100

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, hlist: :zeek:type:`mime_header_list`)

   Generated for HTTP headers, passing on all headers of an HTTP message at
   once. Zeek supports persistent and pipelined HTTP sessions and raises
   corresponding events as it parses client/server dialogues.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the header was sent by the originator of the TCP connection.
   

   :param hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. zeek:see::  http_begin_entity http_content_type http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. zeek:id:: http_begin_entity
   :source-code: base/protocols/http/entities.zeek 73 83

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when starting to parse an HTTP body entity. This event is generated
   at least once for each non-empty (client or server) HTTP body; and
   potentially more than once if the body contains further nested MIME
   entities. Zeek raises this event just before it starts parsing each entity's
   content.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: http_all_headers  http_content_type http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      mime_begin_entity http_connection_upgrade

.. zeek:id:: http_end_entity
   :source-code: base/protocols/http/entities.zeek 214 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when finishing parsing an HTTP body entity. This event is generated
   at least once for each non-empty (client or server) HTTP body; and
   potentially more than once if the body contains further nested MIME
   entities. Zeek raises this event at the point when it has finished parsing an
   entity's content.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_entity_data
      http_event http_header http_message_done http_reply http_request
      http_stats mime_end_entity http_connection_upgrade

.. zeek:id:: http_entity_data
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 170 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated when parsing an HTTP body entity, passing on the data. This event
   can potentially be raised many times for each entity, each time passing a
   chunk of the data of not further defined size.
   
   A common idiom for using this event is to first *reassemble* the data
   at the scripting layer by concatenating it to a successively growing
   string; and only perform further content analysis once the corresponding
   :zeek:id:`http_end_entity` event has been raised. Note, however, that doing so
   can be quite expensive for HTTP tranders. At the very least, one should
   impose an upper size limit on how much data is being buffered.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :param length: The length of *data*.
   

   :param data: One chunk of raw entity data.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_event http_header http_message_done http_reply http_request http_stats
      mime_entity_data http_entity_data_delivery_size skip_http_data
      http_connection_upgrade

.. zeek:id:: http_content_type
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 196 196

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, ty: :zeek:type:`string`, subty: :zeek:type:`string`)

   Generated for reporting an HTTP body's content type.  This event is
   generated at the end of parsing an HTTP header, passing on the MIME
   type as specified by the ``Content-Type`` header. If that header is
   missing, this event is still raised with a default value of ``text/plain``.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :param ty: The main type.
   

   :param subty: The subtype.
   
   .. zeek:see:: http_all_headers http_begin_entity  http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. zeek:id:: http_message_done
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 220 220

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, stat: :zeek:type:`http_message_stat`)

   Generated once at the end of parsing an HTTP message. Zeek supports persistent
   and pipelined HTTP sessions and raises corresponding events as it parses
   client/server dialogues. A "message" is one top-level HTTP entity, such as a
   complete request or reply. Each message can have further nested sub-entities
   inside. This event is raised once all sub-entities belonging to a top-level
   message have been processed (and their corresponding ``http_entity_*`` events
   generated).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :param stat: Further meta information about the message.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header  http_reply http_request http_stats
      http_connection_upgrade

.. zeek:id:: http_event
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 238 238

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, event_type: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for errors found when decoding HTTP requests or replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :param c: The connection.
   

   :param event_type: A string describing the general category of the problem found
               (e.g., ``illegal format``).
   

   :param detail: Further more detailed description of the error.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data  http_header http_message_done http_reply http_request
      http_stats mime_event http_connection_upgrade

.. zeek:id:: http_stats
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, stats: :zeek:type:`http_stats_rec`)

   Generated at the end of an HTTP session to report statistics about it. This
   event is raised after all of an HTTP session's requests and replies have been
   fully processed.
   

   :param c: The connection.
   

   :param stats: Statistics summarizing HTTP-level properties of the finished
          connection.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply
      http_request http_connection_upgrade

.. zeek:id:: http_connection_upgrade
   :source-code: base/bif/plugins/Zeek_HTTP.events.bif.zeek 267 267

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, protocol: :zeek:type:`string`)

   Generated when a HTTP session is upgraded to a different protocol (e.g. websocket).
   This event is raised when a server replies with a HTTP 101 reply. No more HTTP events
   will be raised after this event.
   

   :param c: The connection.
   

   :param protocol: The protocol to which the connection is switching.
   
   .. zeek:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply
      http_request

Functions
+++++++++

.. zeek:id:: skip_http_entity_data
   :source-code: base/bif/plugins/Zeek_HTTP.functions.bif.zeek 14 14

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`) : :zeek:type:`any`

   Skips the data of the HTTP entity.
   

   :param c: The HTTP connection.
   

   :param is_orig: If true, the client data is skipped, and the server data otherwise.
   
   .. zeek:see:: skip_smtp_data

.. zeek:id:: unescape_URI
   :source-code: base/bif/plugins/Zeek_HTTP.functions.bif.zeek 30 30

   :Type: :zeek:type:`function` (URI: :zeek:type:`string`) : :zeek:type:`string`

   Unescapes all characters in a URI (decode every ``%xx`` group).
   

   :param URI: The URI to unescape.
   

   :returns: The unescaped URI with all ``%xx`` groups decoded.
   
   .. note::
   
        Unescaping reserved characters may cause loss of information.
        :rfc:`2396`: A URI is always in an "escaped" form, since escaping or
        unescaping a completed URI might change its semantics.  Normally, the
        only time escape encodings can safely be made is when the URI is
        being created from its component parts.

.. _plugin-zeek-ident:

Zeek::Ident
-----------

Ident analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_IDENT`

Events
++++++

.. zeek:id:: ident_request
   :source-code: base/bif/plugins/Zeek_Ident.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`)

   Generated for Ident requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :param c: The connection.
   

   :param lport: The request's local port.
   

   :param rport: The request's remote port.
   
   .. zeek:see:: ident_error ident_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ident_reply
   :source-code: base/bif/plugins/Zeek_Ident.events.bif.zeek 45 45

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`, user_id: :zeek:type:`string`, system: :zeek:type:`string`)

   Generated for Ident replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :param c: The connection.
   

   :param lport: The corresponding request's local port.
   

   :param rport: The corresponding request's remote port.
   

   :param user_id: The user id returned by the reply.
   

   :param system: The operating system returned by the reply.
   
   .. zeek:see:: ident_error  ident_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ident_error
   :source-code: base/bif/plugins/Zeek_Ident.events.bif.zeek 67 67

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, lport: :zeek:type:`port`, rport: :zeek:type:`port`, line: :zeek:type:`string`)

   Generated for Ident error replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :param c: The connection.
   

   :param lport: The corresponding request's local port.
   

   :param rport: The corresponding request's remote port.
   

   :param line: The error description returned by the reply.
   
   .. zeek:see:: ident_reply ident_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. _plugin-zeek-imap:

Zeek::IMAP
----------

IMAP analyzer (StartTLS only)

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_IMAP`

Events
++++++

.. zeek:id:: imap_capabilities
   :source-code: base/bif/plugins/Zeek_IMAP.events.bif.zeek 10 10

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, capabilities: :zeek:type:`string_vec`)

   Generated when a server sends a capability list to the client,
   after being queried using the CAPABILITY command.
   

   :param c: The connection.
   

   :param capabilities: The list of IMAP capabilities as sent by the server.

.. zeek:id:: imap_starttls
   :source-code: base/bif/plugins/Zeek_IMAP.events.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a IMAP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :param c: The connection.

.. _plugin-zeek-irc:

Zeek::IRC
---------

IRC analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_IRC`

:zeek:enum:`Analyzer::ANALYZER_IRC_DATA`

Events
++++++

.. zeek:id:: irc_request
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 30 30

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, command: :zeek:type:`string`, arguments: :zeek:type:`string`)

   Generated for all client-side IRC commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: Always true.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param command: The command.
   

   :param arguments: The arguments for the command.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack
   
   .. note:: This event is generated only for messages that originate
      at the client-side. Commands coming in from remote trigger
      the :zeek:id:`irc_message` event instead.

.. zeek:id:: irc_reply
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, code: :zeek:type:`count`, params: :zeek:type:`string`)

   Generated for all IRC replies. IRC replies are sent in response to a
   request and come with a reply code.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the reply. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param code: The reply code, as specified by the protocol.
   

   :param params: The reply's parameters.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 86 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, command: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC commands forwarded from the server to the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: Always false.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param command: The command.
   

   :param message: TODO.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message  irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack
   
   .. note::
   
      This event is generated only for messages that are forwarded by the server
      to the client. Commands coming from client trigger the
      :zeek:id:`irc_request` event instead.

.. zeek:id:: irc_quit_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 109 109

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *quit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname coming with the message.
   

   :param message: The text included with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_privmsg_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 134 134

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *privmsg*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param source: The source of the private communication.
   

   :param target: The target of the private communication.
   

   :param message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_notice_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 159 159

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *notice*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param source: The source of the private communication.
   

   :param target: The target of the private communication.
   

   :param message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message  irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_squery_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 184 184

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *squery*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param source: The source of the private communication.
   

   :param target: The target of the private communication.
   

   :param message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_join_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 205 205

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, info_list: :zeek:type:`irc_join_list`)

   Generated for IRC messages of type *join*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param info_list: The user information coming with the command.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_part_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 230 230

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, chans: :zeek:type:`string_set`, message: :zeek:type:`string`)

   Generated for IRC messages of type *part*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname coming with the message.
   

   :param chans: The set of channels affected.
   

   :param message: The text coming with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_nick_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, who: :zeek:type:`string`, newnick: :zeek:type:`string`)

   Generated for IRC messages of type *nick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param who: The user changing its nickname.
   

   :param newnick: The new nickname.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_invalid_nick
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 271 271

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when a server rejects an IRC nickname.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users  irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_network_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 295 295

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, users: :zeek:type:`count`, services: :zeek:type:`count`, servers: :zeek:type:`count`)

   Generated for an IRC reply of type *luserclient*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param users: The number of users as returned in the reply.
   

   :param services: The number of services as returned in the reply.
   

   :param servers: The number of servers as returned in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_server_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 319 319

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, users: :zeek:type:`count`, services: :zeek:type:`count`, servers: :zeek:type:`count`)

   Generated for an IRC reply of type *luserme*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param users: The number of users as returned in the reply.
   

   :param services: The number of services as returned in the reply.
   

   :param servers: The number of servers as returned in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_channel_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 339 339

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, chans: :zeek:type:`count`)

   Generated for an IRC reply of type *luserchannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param chans: The number of channels as returned in the reply.
   
   .. zeek:see::  irc_channel_topic irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_who_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 375 375

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, target_nick: :zeek:type:`string`, channel: :zeek:type:`string`, user: :zeek:type:`string`, host: :zeek:type:`string`, server: :zeek:type:`string`, nick: :zeek:type:`string`, params: :zeek:type:`string`, hops: :zeek:type:`count`, real_name: :zeek:type:`string`)

   Generated for an IRC reply of type *whoreply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param target_nick: The target nickname.
   

   :param channel: The channel.
   

   :param user: The user.
   

   :param host: The host.
   

   :param server: The server.
   

   :param nick: The nickname.
   

   :param params: The parameters.
   

   :param hops: The hop count.
   

   :param real_name: The real name.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_names_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 400 400

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, c_type: :zeek:type:`string`, channel: :zeek:type:`string`, users: :zeek:type:`string_set`)

   Generated for an IRC reply of type *namereply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param c_type: The channel type.
   

   :param channel: The channel.
   

   :param users: The set of users.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message  irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_operator_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 420 420

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`)

   Generated for an IRC reply of type *whoisoperator*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname specified in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_channel_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 442 442

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, chans: :zeek:type:`string_set`)

   Generated for an IRC reply of type *whoischannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname specified in the reply.
   

   :param chans: The set of channels returned.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_user_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 468 468

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, user: :zeek:type:`string`, host: :zeek:type:`string`, real_name: :zeek:type:`string`)

   Generated for an IRC reply of type *whoisuser*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname specified in the reply.
   

   :param user: The user name specified in the reply.
   

   :param host: The host name specified in the reply.
   

   :param real_name: The real name specified in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_oper_response
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 489 489

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, got_oper: :zeek:type:`bool`)

   Generated for IRC replies of type *youreoper* and *nooperhost*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param got_oper: True if the *oper* command was executed successfully
             (*youreport*) and false otherwise (*nooperhost*).
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_global_users
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 512 512

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, msg: :zeek:type:`string`)

   Generated for an IRC reply of type *globalusers*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param msg: The message coming with the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_channel_topic
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 534 534

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, channel: :zeek:type:`string`, topic: :zeek:type:`string`)

   Generated for an IRC reply of type *topic*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param channel: The channel name specified in the reply.
   

   :param topic: The topic specified in the reply.
   
   .. zeek:see:: irc_channel_info  irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_who_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 557 557

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, mask: :zeek:type:`string`, oper: :zeek:type:`bool`)

   Generated for IRC messages of type *who*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param mask: The mask specified in the message.
   

   :param oper: True if the operator flag was set.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 580 580

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, server: :zeek:type:`string`, users: :zeek:type:`string`)

   Generated for IRC messages of type *whois*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param server: TODO.
   

   :param users: TODO.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_oper_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 603 603

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for IRC messages of type *oper*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param user: The user specified in the message.
   

   :param password: The password specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message  irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_kick_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 631 631

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, chans: :zeek:type:`string`, users: :zeek:type:`string`, comment: :zeek:type:`string`)

   Generated for IRC messages of type *kick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param chans: The channels specified in the message.
   

   :param users: The users specified in the message.
   

   :param comment: The comment specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_error_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 655 655

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *error*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param message: The textual description specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_invite_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 681 681

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, nickname: :zeek:type:`string`, channel: :zeek:type:`string`)

   Generated for IRC messages of type *invite*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param nickname: The nickname specified in the message.
   

   :param channel: The channel specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick  irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_mode_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 705 705

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, params: :zeek:type:`string`)

   Generated for IRC messages of type *mode*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param params: The parameters coming with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message  irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_squit_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 731 731

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, server: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *squit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param server: The server specified in the message.
   

   :param message: The textual description specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_dcc_message
   :source-code: base/protocols/irc/dcc-send.zeek 109 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, target: :zeek:type:`string`, dcc_type: :zeek:type:`string`, argument: :zeek:type:`string`, address: :zeek:type:`addr`, dest_port: :zeek:type:`count`, size: :zeek:type:`count`)

   Generated for IRC messages of type *dcc*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Direct_Client-to-Client>`__ for more
   information about the DCC.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param target: The target specified in the message.
   

   :param dcc_type: The DCC type specified in the message.
   

   :param argument:  The argument specified in the message.
   

   :param address: The address specified in the message.
   

   :param dest_port: The destination port specified in the message.
   

   :param size: The size specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic  irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_dcc_send_ack
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 789 789

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, bytes_received: :zeek:type:`count`)

   Generated for IRC messages of type *dcc*. This event is generated for
   DCC SEND acknowledge message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Direct_Client-to-Client>`__ for more
   information about the DCC.
   

   :param c: The connection.
   

   :param bytes_received: The number of bytes received as reported by the recipient.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_user_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 816 816

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, host: :zeek:type:`string`, server: :zeek:type:`string`, real_name: :zeek:type:`string`)

   Generated for IRC messages of type *user*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param user: The user specified in the message.
   

   :param host: The host name specified in the message.
   

   :param server: The server name specified in the message.
   

   :param real_name: The real name specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_password_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 837 837

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, password: :zeek:type:`string`)

   Generated for IRC messages of type *password*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param password: The password specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_dcc_send_ack

.. zeek:id:: irc_starttls
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 845 845

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated if an IRC connection switched to TLS using STARTTLS. After this
   event no more IRC events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :param c: The connection.

.. _plugin-zeek-krb:

Zeek::KRB
---------

Kerberos analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_KRB`

:zeek:enum:`Analyzer::ANALYZER_KRB_TCP`

Options/Constants
+++++++++++++++++

.. zeek:id:: KRB::keytab
   :source-code: base/init-bare.zeek 4945 4945

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``""``

   Kerberos keytab file name. Used to decrypt tickets encountered on the wire.

Types
+++++

.. zeek:type:: KRB::Error_Msg
   :source-code: base/init-bare.zeek 5031 5054

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count` :zeek:attr:`&optional`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count` :zeek:attr:`&optional`
         The message type (30 for ERROR_MSG)

      client_time: :zeek:type:`time` :zeek:attr:`&optional`
         Current time on the client

      server_time: :zeek:type:`time` :zeek:attr:`&optional`
         Current time on the server

      error_code: :zeek:type:`count`
         The specific error code

      client_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm of the ticket

      client_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name on the ticket

      service_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm of the service

      service_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name of the service

      error_text: :zeek:type:`string` :zeek:attr:`&optional`
         Additional text to explain the error

      pa_data: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Optional pre-authentication data

   The data from the ERROR_MSG message. See :rfc:`4120`.

.. zeek:type:: KRB::SAFE_Msg
   :source-code: base/init-bare.zeek 5012 5028

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count`
         The message type (20 for SAFE_MSG)

      data: :zeek:type:`string`
         The application-specific data that is being passed
         from the sender to the receiver

      timestamp: :zeek:type:`time` :zeek:attr:`&optional`
         Current time from the sender of the message

      seq: :zeek:type:`count` :zeek:attr:`&optional`
         Sequence number used to detect replays

      sender: :zeek:type:`KRB::Host_Address` :zeek:attr:`&optional`
         Sender address

      recipient: :zeek:type:`KRB::Host_Address` :zeek:attr:`&optional`
         Recipient address

   The data from the SAFE message. See :rfc:`4120`.

.. zeek:type:: KRB::KDC_Options
   :source-code: base/init-bare.zeek 4947 4978

   :Type: :zeek:type:`record`

      forwardable: :zeek:type:`bool`
         The ticket to be issued should have its forwardable flag set.

      forwarded: :zeek:type:`bool`
         A (TGT) request for forwarding.

      proxiable: :zeek:type:`bool`
         The ticket to be issued should have its proxiable flag set.

      proxy: :zeek:type:`bool`
         A request for a proxy.

      allow_postdate: :zeek:type:`bool`
         The ticket to be issued should have its may-postdate flag set.

      postdated: :zeek:type:`bool`
         A request for a postdated ticket.

      renewable: :zeek:type:`bool`
         The ticket to be issued should have its renewable  flag set.

      opt_hardware_auth: :zeek:type:`bool`
         Reserved for opt_hardware_auth

      disable_transited_check: :zeek:type:`bool`
         Request that the KDC not check the transited field of a TGT against
         the policy of the local realm before it will issue derivative tickets
         based on the TGT.

      renewable_ok: :zeek:type:`bool`
         If a ticket with the requested lifetime cannot be issued, a renewable
         ticket is acceptable

      enc_tkt_in_skey: :zeek:type:`bool`
         The ticket for the end server is to be encrypted in the session key
         from the additional TGT provided

      renew: :zeek:type:`bool`
         The request is for a renewal

      validate: :zeek:type:`bool`
         The request is to validate a postdated ticket.

   KDC Options. See :rfc:`4120`

.. zeek:type:: KRB::AP_Options
   :source-code: base/init-bare.zeek 4981 4986

   :Type: :zeek:type:`record`

      use_session_key: :zeek:type:`bool`
         Indicates that user-to-user-authentication is in use

      mutual_required: :zeek:type:`bool`
         Mutual authentication is required

   AP Options. See :rfc:`4120`

.. zeek:type:: KRB::Type_Value
   :source-code: base/init-bare.zeek 4990 4995

   :Type: :zeek:type:`record`

      data_type: :zeek:type:`count`
         The data type

      val: :zeek:type:`string`
         The data value

   Used in a few places in the Kerberos analyzer for elements
   that have a type and a string value.

.. zeek:type:: KRB::Ticket
   :source-code: base/init-bare.zeek 5057 5070

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      realm: :zeek:type:`string`
         Realm

      service_name: :zeek:type:`string`
         Name of the service

      cipher: :zeek:type:`count`
         Cipher the ticket was encrypted with

      ciphertext: :zeek:type:`string` :zeek:attr:`&optional`
         Cipher text of the ticket

      authenticationinfo: :zeek:type:`string` :zeek:attr:`&optional`
         Authentication info

   A Kerberos ticket. See :rfc:`4120`.

.. zeek:type:: KRB::Ticket_Vector
   :source-code: base/init-bare.zeek 5072 5072

   :Type: :zeek:type:`vector` of :zeek:type:`KRB::Ticket`


.. zeek:type:: KRB::Host_Address
   :source-code: base/init-bare.zeek 5000 5007

   :Type: :zeek:type:`record`

      ip: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         IPv4 or IPv6 address

      netbios: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         NetBIOS address

      unknown: :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Some other type that we don't support yet

   A Kerberos host address See :rfc:`4120`.

.. zeek:type:: KRB::KDC_Request
   :source-code: base/init-bare.zeek 5075 5106

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count`
         The message type (10 for AS_REQ, 12 for TGS_REQ)

      pa_data: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Optional pre-authentication data

      kdc_options: :zeek:type:`KRB::KDC_Options` :zeek:attr:`&optional`
         Options specified in the request

      client_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name on the ticket

      service_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm of the service

      service_name: :zeek:type:`string` :zeek:attr:`&optional`
         Name of the service

      from: :zeek:type:`time` :zeek:attr:`&optional`
         Time the ticket is good from

      till: :zeek:type:`time` :zeek:attr:`&optional`
         Time the ticket is good till

      rtime: :zeek:type:`time` :zeek:attr:`&optional`
         The requested renew-till time

      nonce: :zeek:type:`count` :zeek:attr:`&optional`
         A random nonce generated by the client

      encryption_types: :zeek:type:`vector` of :zeek:type:`count` :zeek:attr:`&optional`
         The desired encryption algorithms, in order of preference

      host_addrs: :zeek:type:`vector` of :zeek:type:`KRB::Host_Address` :zeek:attr:`&optional`
         Any additional addresses the ticket should be valid for

      additional_tickets: :zeek:type:`vector` of :zeek:type:`KRB::Ticket` :zeek:attr:`&optional`
         Additional tickets may be included for certain transactions

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

.. zeek:type:: KRB::KDC_Response
   :source-code: base/init-bare.zeek 5109 5123

   :Type: :zeek:type:`record`

      pvno: :zeek:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :zeek:type:`count`
         The message type (11 for AS_REP, 13 for TGS_REP)

      pa_data: :zeek:type:`vector` of :zeek:type:`KRB::Type_Value` :zeek:attr:`&optional`
         Optional pre-authentication data

      client_realm: :zeek:type:`string` :zeek:attr:`&optional`
         Realm on the ticket

      client_name: :zeek:type:`string`
         Name on the service

      ticket: :zeek:type:`KRB::Ticket`
         The ticket that was issued

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

Events
++++++

.. zeek:id:: krb_as_request
   :source-code: base/protocols/krb/main.zeek 145 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Authentication Server (AS) Request`` as defined
   in :rfc:`4120`. The AS request contains a username of the client
   requesting authentication, and returns an AS reply with an
   encrypted Ticket Granting Ticket (TGT) for that user. The TGT
   can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC request message data structure.
   
   .. zeek:see:: krb_as_response krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_as_response
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 36 36

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Authentication Server (AS) Response`` as defined
   in :rfc:`4120`. Following the AS request for a user, an AS reply
   contains an encrypted Ticket Granting Ticket (TGT) for that user.
   The TGT can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC reply message data structure.
   
   .. zeek:see:: krb_as_request krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_tgs_request
   :source-code: base/protocols/krb/main.zeek 197 215

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Request`` as defined
   in :rfc:`4120`. Following the Authentication Server exchange, if
   successful, the client now has a Ticket Granting Ticket (TGT). To
   authenticate to a Kerberized service, the client requests a Service
   Ticket, which will be returned in the TGS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC request message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_tgs_response
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 71 71

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Response`` as defined
   in :rfc:`4120`. This message returns a Service Ticket to the client,
   which is encrypted with the service's long-term key, and which the
   client can use to authenticate to that service.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos KDC reply message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_ap_request
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 90 90

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ticket: :zeek:type:`KRB::Ticket`, opts: :zeek:type:`KRB::AP_Options`)

   A Kerberos 5 ``Authentication Header (AP) Request`` as defined
   in :rfc:`4120`. This message contains authentication information
   that should be part of the first message in an authenticated
   transaction.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param ticket: The Kerberos ticket being used for authentication.
   

   :param opts: A Kerberos AP options data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_ap_response
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 106 106

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   A Kerberos 5 ``Authentication Header (AP) Response`` as defined
   in :rfc:`4120`. This is used if mutual authentication is desired.
   All of the interesting information in here is encrypted, so the event
   doesn't have much useful data, but it's provided in case it's important
   to know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_priv krb_safe krb_cred krb_error

.. zeek:id:: krb_priv
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 123 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   A Kerberos 5 ``Private Message`` as defined in :rfc:`4120`. This
   is a private (encrypted) application message, so the event doesn't
   have much useful data, but it's provided in case it's important to
   know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param is_orig: Whether the originator of the connection sent this message.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_safe krb_cred krb_error

.. zeek:id:: krb_safe
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 140 140

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`KRB::SAFE_Msg`)

   A Kerberos 5 ``Safe Message`` as defined in :rfc:`4120`. This is a
   safe (checksummed) application message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param is_orig: Whether the originator of the connection sent this message.
   

   :param msg: A Kerberos SAFE message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_cred krb_error

.. zeek:id:: krb_cred
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 157 157

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, tickets: :zeek:type:`KRB::Ticket_Vector`)

   A Kerberos 5 ``Credential Message`` as defined in :rfc:`4120`. This is
   a private (encrypted) message to forward credentials.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param is_orig: Whether the originator of the connection sent this message.
   

   :param tickets: Tickets obtained from the KDC that are being forwarded.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_error

.. zeek:id:: krb_error
   :source-code: base/bif/plugins/Zeek_KRB.events.bif.zeek 171 171

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`KRB::Error_Msg`)

   A Kerberos 5 ``Error Message`` as defined in :rfc:`4120`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :param c: The connection over which this Kerberos message was sent.
   

   :param msg: A Kerberos error message data structure.
   
   .. zeek:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_cred

.. _plugin-zeek-ldap:

Zeek::LDAP
----------

LDAP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_LDAP_TCP`

:zeek:enum:`Analyzer::ANALYZER_LDAP_UDP`

Types
+++++

.. zeek:type:: LDAP::ProtocolOpcode

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LDAP::ProtocolOpcode_BIND_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_BIND_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_UNBIND_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_SEARCH_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_SEARCH_RESULT_ENTRY LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_SEARCH_RESULT_DONE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_MODIFY_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_MODIFY_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_ADD_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_ADD_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_DEL_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_DEL_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_MOD_DN_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_MOD_DN_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_COMPARE_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_COMPARE_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_ABANDON_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_SEARCH_RESULT_REFERENCE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_EXTENDED_REQUEST LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_EXTENDED_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_INTERMEDIATE_RESPONSE LDAP::ProtocolOpcode

      .. zeek:enum:: LDAP::ProtocolOpcode_Undef LDAP::ProtocolOpcode


.. zeek:type:: LDAP::ResultCode

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LDAP::ResultCode_SUCCESS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_OPERATIONS_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_PROTOCOL_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_TIME_LIMIT_EXCEEDED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_SIZE_LIMIT_EXCEEDED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_COMPARE_FALSE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_COMPARE_TRUE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_AUTH_METHOD_NOT_SUPPORTED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_STRONGER_AUTH_REQUIRED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_PARTIAL_RESULTS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_REFERRAL LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ADMIN_LIMIT_EXCEEDED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_UNAVAILABLE_CRITICAL_EXTENSION LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CONFIDENTIALITY_REQUIRED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_SASL_BIND_IN_PROGRESS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NO_SUCH_ATTRIBUTE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_UNDEFINED_ATTRIBUTE_TYPE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INAPPROPRIATE_MATCHING LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CONSTRAINT_VIOLATION LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ATTRIBUTE_OR_VALUE_EXISTS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INVALID_ATTRIBUTE_SYNTAX LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NO_SUCH_OBJECT LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ALIAS_PROBLEM LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INVALID_DNSYNTAX LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ALIAS_DEREFERENCING_PROBLEM LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INAPPROPRIATE_AUTHENTICATION LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INVALID_CREDENTIALS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INSUFFICIENT_ACCESS_RIGHTS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_BUSY LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_UNAVAILABLE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_UNWILLING_TO_PERFORM LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_LOOP_DETECT LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_SORT_CONTROL_MISSING LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_OFFSET_RANGE_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NAMING_VIOLATION LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_OBJECT_CLASS_VIOLATION LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NOT_ALLOWED_ON_NON_LEAF LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NOT_ALLOWED_ON_RDN LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ENTRY_ALREADY_EXISTS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_OBJECT_CLASS_MODS_PROHIBITED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_RESULTS_TOO_LARGE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_AFFECTS_MULTIPLE_DSAS LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CONTROL_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_OTHER LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_SERVER_DOWN LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_LOCAL_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ENCODING_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_DECODING_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_TIMEOUT LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_AUTH_UNKNOWN LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_FILTER_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_USER_CANCELED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_PARAM_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NO_MEMORY LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CONNECT_ERROR LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NOT_SUPPORTED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CONTROL_NOT_FOUND LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NO_RESULTS_RETURNED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_MORE_RESULTS_TO_RETURN LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CLIENT_LOOP LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_REFERRAL_LIMIT_EXCEEDED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INVALID_RESPONSE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_AMBIGUOUS_RESPONSE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_TLS_NOT_SUPPORTED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_INTERMEDIATE_RESPONSE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_UNKNOWN_TYPE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_LCUP_INVALID_DATA LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_LCUP_UNSUPPORTED_SCHEME LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_LCUP_RELOAD_REQUIRED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CANCELED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_NO_SUCH_OPERATION LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_TOO_LATE LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_CANNOT_CANCEL LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_ASSERTION_FAILED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_AUTHORIZATION_DENIED LDAP::ResultCode

      .. zeek:enum:: LDAP::ResultCode_Undef LDAP::ResultCode


.. zeek:type:: LDAP::BindAuthType

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LDAP::BindAuthType_BIND_AUTH_SIMPLE LDAP::BindAuthType

      .. zeek:enum:: LDAP::BindAuthType_BIND_AUTH_SASL LDAP::BindAuthType

      .. zeek:enum:: LDAP::BindAuthType_SICILY_PACKAGE_DISCOVERY LDAP::BindAuthType

      .. zeek:enum:: LDAP::BindAuthType_SICILY_NEGOTIATE LDAP::BindAuthType

      .. zeek:enum:: LDAP::BindAuthType_SICILY_RESPONSE LDAP::BindAuthType

      .. zeek:enum:: LDAP::BindAuthType_Undef LDAP::BindAuthType


.. zeek:type:: LDAP::SearchScope

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LDAP::SearchScope_SEARCH_BASE LDAP::SearchScope

      .. zeek:enum:: LDAP::SearchScope_SEARCH_SINGLE LDAP::SearchScope

      .. zeek:enum:: LDAP::SearchScope_SEARCH_TREE LDAP::SearchScope

      .. zeek:enum:: LDAP::SearchScope_Undef LDAP::SearchScope


.. zeek:type:: LDAP::SearchDerefAlias

   :Type: :zeek:type:`enum`

      .. zeek:enum:: LDAP::SearchDerefAlias_DEREF_NEVER LDAP::SearchDerefAlias

      .. zeek:enum:: LDAP::SearchDerefAlias_DEREF_IN_SEARCHING LDAP::SearchDerefAlias

      .. zeek:enum:: LDAP::SearchDerefAlias_DEREF_FINDING_BASE LDAP::SearchDerefAlias

      .. zeek:enum:: LDAP::SearchDerefAlias_DEREF_ALWAYS LDAP::SearchDerefAlias

      .. zeek:enum:: LDAP::SearchDerefAlias_Undef LDAP::SearchDerefAlias


.. zeek:type:: ASN1::ASN1Type

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ASN1::ASN1Type_Boolean ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_Integer ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_BitString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_OctetString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_NullVal ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_ObjectIdentifier ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_ObjectDescriptor ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_InstanceOf ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_Real ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_Enumerated ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_EmbeddedPDV ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_UTF8String ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_RelativeOID ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_Sequence ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_Set ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_NumericString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_PrintableString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_TeletextString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_VideotextString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_IA5String ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_UTCTime ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_GeneralizedTime ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_GraphicString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_VisibleString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_GeneralString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_UniversalString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_CharacterString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_BMPString ASN1::ASN1Type

      .. zeek:enum:: ASN1::ASN1Type_Undef ASN1::ASN1Type


.. zeek:type:: ASN1::ASN1Class

   :Type: :zeek:type:`enum`

      .. zeek:enum:: ASN1::ASN1Class_Universal ASN1::ASN1Class

      .. zeek:enum:: ASN1::ASN1Class_Application ASN1::ASN1Class

      .. zeek:enum:: ASN1::ASN1Class_ContextSpecific ASN1::ASN1Class

      .. zeek:enum:: ASN1::ASN1Class_Private ASN1::ASN1Class

      .. zeek:enum:: ASN1::ASN1Class_Undef ASN1::ASN1Class


Events
++++++

.. zeek:id:: LDAP::message
   :source-code: base/protocols/ldap/main.zeek 188 283

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, message_id: :zeek:type:`int`, opcode: :zeek:type:`LDAP::ProtocolOpcode`, result: :zeek:type:`LDAP::ResultCode`, matched_dn: :zeek:type:`string`, diagnostic_message: :zeek:type:`string`, object: :zeek:type:`string`, argument: :zeek:type:`string`)

   Event generated for each LDAPMessage (either direction).
   

   :param c: The connection.
   

   :param message_id: The messageID element.
   

   :param opcode: The protocolOp field in the message.
   

   :param result: The result code if the message contains a result.
   

   :param matched_dn: The DN if the message contains a result.
   

   :param diagnostic_message: Diagnostic message if the LDAP message contains a result.
   

   :param object: The object name this message refers to.
   

   :param argument: Additional arguments this message includes.

.. zeek:id:: LDAP::bind_request
   :source-code: base/protocols/ldap/main.zeek 362 393

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, message_id: :zeek:type:`int`, version: :zeek:type:`int`, name: :zeek:type:`string`, auth_type: :zeek:type:`LDAP::BindAuthType`, auth_info: :zeek:type:`string`)

   Event generated for each LDAPMessage containing a BindRequest.
   

   :param c: The connection.
   

   :param message_id: The messageID element.
   

   :param version: The version field in the BindRequest.
   

   :param name: The name field in the BindRequest.
   

   :param auth_type: The auth type field in the BindRequest.
   

   :param auth_info: Additional information related to the used auth type.

.. zeek:id:: LDAP::search_request
   :source-code: base/protocols/ldap/main.zeek 295 344

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, message_id: :zeek:type:`int`, base_object: :zeek:type:`string`, scope: :zeek:type:`LDAP::SearchScope`, deref: :zeek:type:`LDAP::SearchDerefAlias`, size_limit: :zeek:type:`int`, time_limit: :zeek:type:`int`, types_only: :zeek:type:`bool`, filter: :zeek:type:`string`, attributes: :zeek:type:`vector` of :zeek:type:`string`)

   Event generated for each LDAPMessage containing a SearchRequest.
   

   :param c: The connection.
   

   :param message_id: The messageID element.
   

   :param base_object: The baseObject field in the SearchRequest.
   

   :param scope: The scope field in the SearchRequest.
   

   :param deref_alias: The derefAlias field in the SearchRequest
   

   :param size_limit: The sizeLimit field in the SearchRequest.
   

   :param time_limit: The timeLimit field in the SearchRequest.
   

   :param types_only: The typesOnly field in the SearchRequest.
   

   :param filter: The string representation of the filter field in the SearchRequest.
   

   :param attributes: Additional attributes of the SearchRequest.

.. zeek:id:: LDAP::search_result_entry
   :source-code: base/protocols/ldap/main.zeek 349 354

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, message_id: :zeek:type:`int`, object_name: :zeek:type:`string`)

   Event generated for each SearchResultEntry in LDAP messages.
   

   :param c: The connection.
   

   :param message_id: The messageID element.
   

   :param object_name: The object name in the SearchResultEntry.

.. zeek:id:: LDAP::extended_request
   :source-code: base/protocols/ldap/spicy-events.zeek 111 111

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, message_id: :zeek:type:`int`, request_name: :zeek:type:`string`, request_value: :zeek:type:`string`)

   Event generated for each ExtendedRequest in LDAP messages.
   

   :param c: The connection.
   

   :param message_id: The messageID element.
   

   :param request_name: The name of the extended request.
   

   :param request_value: The value of the extended request (empty if missing).

.. zeek:id:: LDAP::extended_response
   :source-code: base/protocols/ldap/spicy-events.zeek 129 129

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, message_id: :zeek:type:`int`, result: :zeek:type:`LDAP::ResultCode`, response_name: :zeek:type:`string`, response_value: :zeek:type:`string`)

   Event generated for each ExtendedResponse in LDAP messages.
   

   :param c: The connection.
   

   :param message_id: The messageID element.
   

   :param result: The result code of the response.
   

   :param response_name: The name of the extended response (empty if missing).
   

   :param response_value: The value of the extended response (empty if missing).

.. zeek:id:: LDAP::starttls
   :source-code: base/protocols/ldap/spicy-events.zeek 141 141

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Event generated when a plaintext LDAP connection switched to TLS.
   

   :param c: The connection.
   

.. _plugin-zeek-login:

Zeek::Login
-----------

Telnet/Rsh/Rlogin analyzers

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_RLOGIN`

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_RSH`

:zeek:enum:`Analyzer::ANALYZER_LOGIN`

:zeek:enum:`Analyzer::ANALYZER_NVT`

:zeek:enum:`Analyzer::ANALYZER_RLOGIN`

:zeek:enum:`Analyzer::ANALYZER_RSH`

:zeek:enum:`Analyzer::ANALYZER_TELNET`

Events
++++++

.. zeek:id:: rsh_request
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, client_user: :zeek:type:`string`, server_user: :zeek:type:`string`, line: :zeek:type:`string`, new_session: :zeek:type:`bool`)

   Generated for client side commands on an RSH connection.
   
   See :rfc:`1258` for more information about the Rlogin/Rsh protocol.
   

   :param c: The connection.
   

   :param client_user: The client-side user name as sent in the initial protocol
         handshake.
   

   :param server_user: The server-side user name as sent in the initial protocol
         handshake.
   

   :param line: The command line sent in the request.
   

   :param new_session: True if this is the first command of the Rsh session.
   
   .. zeek:see:: rsh_reply login_confused login_confused_text login_display
      login_failure login_input_line login_output_line login_prompt login_success
      login_terminal
   
   .. note:: For historical reasons, these events are separate from the
      ``login_`` events. Ideally, they would all be handled uniquely.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: rsh_reply
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 59 59

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, client_user: :zeek:type:`string`, server_user: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated for client side commands on an RSH connection.
   
   See :rfc:`1258` for more information about the Rlogin/Rsh protocol.
   

   :param c: The connection.
   

   :param client_user: The client-side user name as sent in the initial protocol
         handshake.
   

   :param server_user: The server-side user name as sent in the initial protocol
         handshake.
   

   :param line: The command line sent in the request.
   
   .. zeek:see:: rsh_request login_confused login_confused_text login_display
      login_failure login_input_line login_output_line login_prompt login_success
      login_terminal
   
   .. note:: For historical reasons, these events are separate from the
      ``login_`` events. Ideally, they would all be handled uniquely.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: login_failure
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 95 95

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, client_user: :zeek:type:`string`, password: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated for Telnet/Rlogin login failures. The *login* analyzer inspects
   Telnet/Rlogin sessions to heuristically extract username and password
   information as well as the text returned by the login server. This event is
   raised if a login attempt appears to have been unsuccessful.
   

   :param c: The connection.
   

   :param user: The user name tried.
   

   :param client_user: For Telnet connections, this is an empty string, but for Rlogin
         connections, it is the client name passed in the initial authentication
         information (to check against .rhosts).
   

   :param password:  The password tried.
   

   :param line:  The line of text that led the analyzer to conclude that the
          authentication had failed.
   
   .. zeek:see:: login_confused login_confused_text login_display login_input_line
      login_output_line login_prompt login_success login_terminal direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts login_success_msgs
      login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying login attempts. This
      configuration has not yet been ported, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Zeeks's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_success
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 131 131

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, client_user: :zeek:type:`string`, password: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated for successful Telnet/Rlogin logins. The *login* analyzer inspects
   Telnet/Rlogin sessions to heuristically extract username and password
   information as well as the text returned by the login server. This event is
   raised if a login attempt appears to have been successful.
   

   :param c: The connection.
   

   :param user: The user name used.
   

   :param client_user: For Telnet connections, this is an empty string, but for Rlogin
         connections, it is the client name passed in the initial authentication
         information (to check against .rhosts).
   

   :param password: The password used.
   

   :param line:  The line of text that led the analyzer to conclude that the
          authentication had succeeded.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line login_prompt login_terminal
      direct_login_prompts get_login_state login_failure_msgs login_non_failure_msgs
      login_prompts login_success_msgs login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying login attempts. This
      configuration has not yet been ported, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_input_line
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 149 149

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, line: :zeek:type:`string`)

   Generated for lines of input on Telnet/Rlogin sessions. The line will have
   control characters (such as in-band Telnet options) removed.
   

   :param c: The connection.
   

   :param line: The input line.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_output_line login_prompt login_success login_terminal    rsh_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_output_line
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 167 167

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, line: :zeek:type:`string`)

   Generated for lines of output on Telnet/Rlogin sessions. The line will have
   control characters (such as in-band Telnet options) removed.
   

   :param c: The connection.
   

   :param line: The output line.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line  login_prompt login_success login_terminal rsh_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_confused
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 195 195

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`, line: :zeek:type:`string`)

   Generated when tracking of Telnet/Rlogin authentication failed. As Zeek's
   *login* analyzer uses a number of heuristics to extract authentication
   information, it may become confused. If it can no longer correctly track
   the authentication dialog, it raises this event.
   

   :param c: The connection.
   

   :param msg: Gives the particular problem the heuristics detected (for example,
        ``multiple_login_prompts`` means that the engine saw several login
        prompts in a row, without the type-ahead from the client side presumed
        necessary to cause them)
   

   :param line: The line of text that caused the heuristics to conclude they were
         confused.
   
   .. zeek:see::  login_confused_text login_display login_failure login_input_line login_output_line
      login_prompt login_success login_terminal direct_login_prompts get_login_state
      login_failure_msgs login_non_failure_msgs login_prompts login_success_msgs
      login_timeouts set_login_state
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_confused_text
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 217 217

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, line: :zeek:type:`string`)

   Generated after getting confused while tracking a Telnet/Rlogin
   authentication dialog. The *login* analyzer generates this even for every
   line of user input after it has reported :zeek:id:`login_confused` for a
   connection.
   

   :param c: The connection.
   

   :param line: The line the user typed.
   
   .. zeek:see:: login_confused  login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts
      login_success_msgs login_timeouts set_login_state
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_terminal
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 235 235

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, terminal: :zeek:type:`string`)

   Generated for clients transmitting a terminal type in a Telnet session.  This
   information is extracted out of environment variables sent as Telnet options.
   

   :param c: The connection.
   

   :param terminal: The TERM value transmitted.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line login_prompt login_success
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_display
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, display: :zeek:type:`string`)

   Generated for clients transmitting an X11 DISPLAY in a Telnet session. This
   information is extracted out of environment variables sent as Telnet options.
   

   :param c: The connection.
   

   :param display: The DISPLAY transmitted.
   
   .. zeek:see:: login_confused login_confused_text  login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: authentication_accepted
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 279 279

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, c: :zeek:type:`connection`)

   Generated when a Telnet authentication has been successful. The Telnet
   protocol includes options for negotiating authentication. When such an
   option is sent from client to server and the server replies that it accepts
   the authentication, then the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param name: The authenticated name.
   

   :param c: The connection.
   
   .. zeek:see::  authentication_rejected authentication_skipped login_success
   
   .. note::  This event inspects the corresponding Telnet option
      while :zeek:id:`login_success` heuristically determines success by watching
      session data.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: authentication_rejected
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 305 305

   :Type: :zeek:type:`event` (name: :zeek:type:`string`, c: :zeek:type:`connection`)

   Generated when a Telnet authentication has been unsuccessful. The Telnet
   protocol includes options for negotiating authentication. When such an option
   is sent from client to server and the server replies that it did not accept
   the authentication, then the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param name: The attempted authentication name.
   

   :param c: The connection.
   
   .. zeek:see:: authentication_accepted authentication_skipped login_failure
   
   .. note::  This event inspects the corresponding Telnet option
      while :zeek:id:`login_success` heuristically determines failure by watching
      session data.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: authentication_skipped
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 330 330

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for Telnet/Rlogin sessions when a pattern match indicates
   that no authentication is performed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: authentication_accepted authentication_rejected direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts
      login_success_msgs login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying activity. This
      configuration has not yet been ported, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: login_prompt
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 352 352

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, prompt: :zeek:type:`string`)

   Generated for clients transmitting a terminal prompt in a Telnet session.
   This information is extracted out of environment variables sent as Telnet
   options.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   

   :param prompt: The TTYPROMPT transmitted.
   
   .. zeek:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line  login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: activating_encryption
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 367 367

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for Telnet sessions when encryption is activated. The Telnet
   protocol includes options for negotiating encryption. When such a series of
   options is successfully negotiated, the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: authentication_accepted authentication_rejected authentication_skipped
      login_confused login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal

.. zeek:id:: inconsistent_option
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 387 387

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for an inconsistent Telnet option. Telnet options are specified
   by the client and server stating which options they are willing to
   support vs. which they are not, and then instructing one another which in
   fact they should or should not use for the current connection. If the event
   engine sees a peer violate either what the other peer has instructed it to
   do, or what it itself offered in terms of options in the past, then the
   engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: bad_option bad_option_termination  authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal

.. zeek:id:: bad_option
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 407 407

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for an ill-formed or unrecognized Telnet option.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: inconsistent_option bad_option_termination authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: bad_option_termination
   :source-code: base/bif/plugins/Zeek_Login.events.bif.zeek 427 427

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a Telnet option that's incorrectly terminated.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :param c: The connection.
   
   .. zeek:see:: inconsistent_option bad_option authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

Functions
+++++++++

.. zeek:id:: get_login_state
   :source-code: base/bif/plugins/Zeek_Login.functions.bif.zeek 26 26

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`count`

   Returns the state of the given login (Telnet or Rlogin) connection.
   

   :param cid: The connection ID.
   

   :returns: False if the connection is not active or is not tagged as a
            login analyzer. Otherwise the function returns the state, which can
            be one of:
   
                - ``LOGIN_STATE_AUTHENTICATE``: The connection is in its
                  initial authentication dialog.
                - ``LOGIN_STATE_LOGGED_IN``: The analyzer believes the user has
                  successfully authenticated.
                - ``LOGIN_STATE_SKIP``: The analyzer has skipped any further
                  processing of the connection.
                - ``LOGIN_STATE_CONFUSED``: The analyzer has concluded that it
                  does not correctly know the state of the connection, and/or
                  the username associated with it.
   
   .. zeek:see:: set_login_state

.. zeek:id:: set_login_state
   :source-code: base/bif/plugins/Zeek_Login.functions.bif.zeek 40 40

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, new_state: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the login state of a connection with a login analyzer.
   

   :param cid: The connection ID.
   

   :param new_state: The new state of the login analyzer. See
              :zeek:id:`get_login_state` for possible values.
   

   :returns: Returns false if *cid* is not an active connection
            or is not tagged as a login analyzer, and true otherwise.
   
   .. zeek:see:: get_login_state

.. _plugin-zeek-mime:

Zeek::MIME
----------

MIME parsing

Components
++++++++++

Options/Constants
+++++++++++++++++

.. zeek:id:: MIME::max_depth
   :source-code: base/init-bare.zeek 2837 2837

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   Stop analysis of nested multipart MIME entities if this depth is
   reached. Setting this value to 0 removes the limit.

Events
++++++

.. zeek:id:: mime_begin_entity
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when starting to parse an email MIME entity. MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Zeek raises this event when it
   begins parsing a MIME entity extracted from an email protocol.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   
   .. zeek:see:: mime_all_data mime_all_headers  mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_begin_entity
   
   .. note:: Zeek also extracts MIME entities from HTTP sessions. For those,
      however, it raises :zeek:id:`http_begin_entity` instead.

.. zeek:id:: mime_end_entity
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 41 41

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when finishing parsing an email MIME entity.  MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Zeek raises this event when it
   finished parsing a MIME entity extracted from an email protocol.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_end_entity
   
   .. note:: Zeek also extracts MIME entities from HTTP sessions. For those,
      however, it raises :zeek:id:`http_end_entity` instead.

.. zeek:id:: mime_one_header
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 62 62

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, h: :zeek:type:`mime_header_rec`)

   Generated for individual MIME headers extracted from email MIME
   entities.  MIME is a protocol-independent data format for encoding text and
   files, along with corresponding metadata, for transmission.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param h: The parsed MIME header.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event  mime_segment_data
      http_header  http_all_headers
   
   .. note:: Zeek also extracts MIME headers from HTTP sessions. For those,
      however, it raises :zeek:id:`http_header` instead.

.. zeek:id:: mime_all_headers
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 85 85

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hlist: :zeek:type:`mime_header_list`)

   Generated for MIME headers extracted from email MIME entities, passing all
   headers at once.  MIME is a protocol-independent data format for encoding
   text and files, along with corresponding metadata, for transmission.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. zeek:see:: mime_all_data  mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
      http_header  http_all_headers
   
   .. note:: Zeek also extracts MIME headers from HTTP sessions. For those,
      however, it raises :zeek:id:`http_header` instead.

.. zeek:id:: mime_segment_data
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 114 114

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for chunks of decoded MIME data from email MIME entities.  MIME
   is a protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. As Zeek parses the data of an
   entity, it raises a sequence of these events, each coming as soon as a new
   chunk of data is available. In contrast, there is also
   :zeek:id:`mime_entity_data`, which passes all of an entities data at once
   in a single block. While the latter is more convenient to handle,
   ``mime_segment_data`` is more efficient as Zeek does not need to buffer
   the data. Thus, if possible, this event should be preferred.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param length: The length of *data*.
   

   :param data: The raw data of one segment of the current entity.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header http_entity_data
      mime_segment_length mime_segment_overlap_length
   
   .. note:: Zeek also extracts MIME data from HTTP sessions. For those,
      however, it raises :zeek:id:`http_entity_data` (sic!) instead.

.. zeek:id:: mime_entity_data
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 140 140

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for data decoded from an email MIME entity. This event delivers
   the complete content of a single MIME entity with the quoted-printable and
   and base64 data decoded. In contrast, there is also :zeek:id:`mime_segment_data`,
   which passes on a sequence of data chunks as they come in. While
   ``mime_entity_data`` is more convenient to handle, ``mime_segment_data`` is
   more efficient as Zeek does not need to buffer the data. Thus, if possible,
   the latter should be preferred.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param length: The length of *data*.
   

   :param data: The raw data of the complete entity.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity  mime_event mime_one_header mime_segment_data
   
   .. note:: While Zeek also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. zeek:id:: mime_all_data
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 164 164

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, length: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for passing on all data decoded from a single email MIME
   message. If an email message has more than one MIME entity, this event
   combines all their data into a single value for analysis. Note that because
   of the potentially significant buffering necessary, using this event can be
   expensive.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param length: The length of *data*.
   

   :param data: The raw data of all MIME entities concatenated.
   
   .. zeek:see::  mime_all_headers mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Zeek also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. zeek:id:: mime_event
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 185 185

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, event_type: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for errors found when decoding email MIME entities.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param event_type: A string describing the general category of the problem found
      (e.g., ``illegal format``).
   

   :param detail: Further more detailed description of the error.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data  mime_one_header mime_segment_data http_event
   
   .. note:: Zeek also extracts MIME headers from HTTP sessions. For those,
      however, it raises :zeek:id:`http_event` instead.

.. zeek:id:: mime_content_hash
   :source-code: base/bif/plugins/Zeek_MIME.events.bif.zeek 207 207

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, content_len: :zeek:type:`count`, hash_value: :zeek:type:`string`)

   Generated for decoded MIME entities extracted from email messages, passing on
   their MD5 checksums. Zeek computes the MD5 over the complete decoded data of
   each MIME entity.
   
   Zeek's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :param c: The connection.
   

   :param content_len: The length of the entity being hashed.
   

   :param hash_value: The MD5 hash.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Zeek also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. _plugin-zeek-modbus:

Zeek::Modbus
------------

Modbus analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_MODBUS`

Events
++++++

.. zeek:id:: modbus_message
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 12 12

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, is_orig: :zeek:type:`bool`)

   Generated for any Modbus message regardless if the particular function
   is further supported or not.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param is_orig: True if the event is raised for the originator side.

.. zeek:id:: modbus_exception
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 22 22

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, code: :zeek:type:`count`)

   Generated for any Modbus exception message.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param code: The exception code.

.. zeek:id:: modbus_read_coils_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read coils request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil to be read.
   

   :param quantity: The number of coils to be read.

.. zeek:id:: modbus_read_coils_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 44 44

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus read coils response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param coils: The coil values returned from the device.

.. zeek:id:: modbus_read_discrete_inputs_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read discrete inputs request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil to be read.
   

   :param quantity: The number of coils to be read.

.. zeek:id:: modbus_read_discrete_inputs_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 66 66

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus read discrete inputs response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param coils: The coil values returned from the device.

.. zeek:id:: modbus_read_holding_registers_request
   :source-code: policy/protocols/modbus/track-memmap.zeek 62 65

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read holding registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register to be read.
   

   :param quantity: The number of registers to be read.

.. zeek:id:: modbus_read_holding_registers_response
   :source-code: policy/protocols/modbus/track-memmap.zeek 67 101

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read holding registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param registers: The register values returned from the device.

.. zeek:id:: modbus_read_input_registers_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 100 100

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus read input registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register to be read.
   

   :param quantity: The number of registers to be read.

.. zeek:id:: modbus_read_input_registers_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 110 110

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read input registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param registers: The register values returned from the device.

.. zeek:id:: modbus_write_single_coil_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 122 122

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`bool`)

   Generated for a Modbus write single coil request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the coil to be written.
   

   :param value: The value to be written to the coil.

.. zeek:id:: modbus_write_single_coil_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 134 134

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`bool`)

   Generated for a Modbus write single coil response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the coil that was written.
   

   :param value: The value that was written to the coil.

.. zeek:id:: modbus_write_single_register_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 146 146

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for a Modbus write single register request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register to be written.
   

   :param value: The value to be written to the register.

.. zeek:id:: modbus_write_single_register_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 158 158

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, value: :zeek:type:`count`)

   Generated for a Modbus write single register response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register that was written.
   

   :param value: The value that was written to the register.

.. zeek:id:: modbus_write_multiple_coils_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 170 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, coils: :zeek:type:`ModbusCoils`)

   Generated for a Modbus write multiple coils request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil to be written.
   

   :param coils: The values to be written to the coils.

.. zeek:id:: modbus_write_multiple_coils_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 182 182

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus write multiple coils response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first coil that was written.
   

   :param quantity: The quantity of coils that were written.

.. zeek:id:: modbus_write_multiple_registers_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 194 194

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus write multiple registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register to be written.
   

   :param registers: The values to be written to the registers.

.. zeek:id:: modbus_write_multiple_registers_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 206 206

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`, quantity: :zeek:type:`count`)

   Generated for a Modbus write multiple registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The memory address of the first register that was written.
   

   :param quantity: The quantity of registers that were written.

.. zeek:id:: modbus_read_file_record_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 218 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileRecordRequests`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus read file record request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_read_file_record_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 232 232

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileRecordResponses`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus read file record response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_write_file_record_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 246 246

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileReferences`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus write file record request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_write_file_record_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 260 260

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, byte_count: :zeek:type:`count`, refs: :zeek:type:`ModbusFileReferences`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`)

   Generated for a Modbus write file record response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param byte_count: The full byte count for all of the reference records that follow.
   

   :param refs: A vector of reference records.

.. zeek:id:: modbus_mask_write_register_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 276 276

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, and_mask: :zeek:type:`count`, or_mask: :zeek:type:`count`)

   Generated for a Modbus mask write register request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register where the masks should be applied.
   

   :param and_mask: The value of the logical AND mask to apply to the register.
   

   :param or_mask: The value of the logical OR mask to apply to the register.

.. zeek:id:: modbus_mask_write_register_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 290 290

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, address: :zeek:type:`count`, and_mask: :zeek:type:`count`, or_mask: :zeek:type:`count`)

   Generated for a Modbus mask write register request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param address: The memory address of the register where the masks were applied.
   

   :param and_mask: The value of the logical AND mask applied register.
   

   :param or_mask: The value of the logical OR mask applied to the register.

.. zeek:id:: modbus_read_write_multiple_registers_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 306 306

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, read_start_address: :zeek:type:`count`, read_quantity: :zeek:type:`count`, write_start_address: :zeek:type:`count`, write_registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param read_start_address: The memory address of the first register to be read.
   

   :param read_quantity: The number of registers to read.
   

   :param write_start_address: The memory address of the first register to be written.
   

   :param write_registers: The values to be written to the registers.

.. zeek:id:: modbus_read_write_multiple_registers_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 317 317

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, written_registers: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param written_registers: The register values read from the registers specified in
                      the request.

.. zeek:id:: modbus_read_fifo_queue_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 327 327

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, start_address: :zeek:type:`count`)

   Generated for a Modbus read FIFO queue request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param start_address: The address of the FIFO queue to read.

.. zeek:id:: modbus_read_fifo_queue_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 337 337

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, fifos: :zeek:type:`ModbusRegisters`)

   Generated for a Modbus read FIFO queue response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param fifos: The register values read from the FIFO queue on the device.

.. zeek:id:: modbus_diagnostics_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 349 349

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, subfunction: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Diagnostics request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param subfunction: The subfunction for the diagnostics request.
   

   :param data: The data passed in the diagnostics request.

.. zeek:id:: modbus_diagnostics_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 361 361

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, subfunction: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Diagnostics response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param subfunction: The subfunction for the diagnostics response.
   

   :param data: The data passed in the diagnostics response.

.. zeek:id:: modbus_encap_interface_transport_request
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 373 373

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, mei_type: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Encapsulated Interface Transport request.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param mei_type: The MEI type for the request.
   

   :param data: The MEI type specific data passed in the request.

.. zeek:id:: modbus_encap_interface_transport_response
   :source-code: base/bif/plugins/Zeek_Modbus.events.bif.zeek 385 385

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, headers: :zeek:type:`ModbusHeaders`, mei_type: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for a Modbus Encapsulated Interface Transport response.
   

   :param c: The connection.
   

   :param headers: The headers for the modbus function.
   

   :param mei_type: The MEI type for the response.
   

   :param data: The MEI type specific data passed in the response.

.. _plugin-zeek-mqtt:

Zeek::MQTT
----------

Message Queuing Telemetry Transport v3.1.1 Protocol analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_MQTT`

Types
+++++

.. zeek:type:: MQTT::ConnectMsg
   :source-code: base/init-bare.zeek 5650 5680

   :Type: :zeek:type:`record`

      protocol_name: :zeek:type:`string`
         Protocol name

      protocol_version: :zeek:type:`count`
         Protocol version

      client_id: :zeek:type:`string`
         Identifies the Client to the Server.

      keep_alive: :zeek:type:`interval`
         The maximum time interval that is permitted to elapse between the
         point at which the Client finishes transmitting one Control Packet
         and the point it starts sending the next.

      clean_session: :zeek:type:`bool`
         The clean_session flag indicates if the server should or shouldn't
         use a clean session or use existing previous session state.

      will_retain: :zeek:type:`bool`
         Specifies if the Will Message is to be retained when it is published.

      will_qos: :zeek:type:`count`
         Specifies the QoS level to be used when publishing the Will Message.

      will_topic: :zeek:type:`string` :zeek:attr:`&optional`
         Topic to publish the Will message to.

      will_msg: :zeek:type:`string` :zeek:attr:`&optional`
         The actual Will message to publish.

      username: :zeek:type:`string` :zeek:attr:`&optional`
         Username to use for authentication to the server.

      password: :zeek:type:`string` :zeek:attr:`&optional`
         Pass to use for authentication to the server.


.. zeek:type:: MQTT::ConnectAckMsg
   :source-code: base/init-bare.zeek 5682 5691

   :Type: :zeek:type:`record`

      return_code: :zeek:type:`count`
         Return code from the connack message

      session_present: :zeek:type:`bool`
         The Session present flag helps the client
         establish whether the Client and Server
         have a consistent view about whether there
         is already stored Session state.


.. zeek:type:: MQTT::PublishMsg
   :source-code: base/init-bare.zeek 5693 5715

   :Type: :zeek:type:`record`

      dup: :zeek:type:`bool`
         Indicates if this is the first attempt at publishing the message.

      qos: :zeek:type:`count`
         Indicates what level of QoS is enabled for this message.

      retain: :zeek:type:`bool`
         Indicates if the server should retain this message so that clients
         subscribing to the topic in the future will receive this message
         automatically.

      topic: :zeek:type:`string`
         Name of the topic the published message is directed into.

      payload: :zeek:type:`string`
         Payload of the published message.

      payload_len: :zeek:type:`count`
         The actual length of the payload in the case the *payload*
         field's contents were truncated according to
         :zeek:see:`MQTT::max_payload_size`.


Events
++++++

.. zeek:id:: mqtt_connect
   :source-code: base/protocols/mqtt/main.zeek 177 188

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`MQTT::ConnectMsg`)

   Generated for MQTT "client requests a connection" messages
   

   :param c: The connection
   

   :param msg: MQTT connect message fields.

.. zeek:id:: mqtt_connack
   :source-code: base/protocols/mqtt/main.zeek 190 197

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`MQTT::ConnectAckMsg`)

   Generated for MQTT acknowledge connection messages
   

   :param c: The connection
   

   :param msg: MQTT connect ack message fields.

.. zeek:id:: mqtt_publish
   :source-code: base/bif/plugins/Zeek_MQTT.events.bif.zeek 27 27

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_id: :zeek:type:`count`, msg: :zeek:type:`MQTT::PublishMsg`)

   Generated for MQTT publish messages
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg: The MQTT publish message record.

.. zeek:id:: mqtt_puback
   :source-code: base/bif/plugins/Zeek_MQTT.events.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_id: :zeek:type:`count`)

   Generated for MQTT publish acknowledgement messages
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg_id: The id value for the message.

.. zeek:id:: mqtt_pubrec
   :source-code: base/protocols/mqtt/main.zeek 257 266

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_id: :zeek:type:`count`)

   Generated for MQTT publish received messages (QoS 2 publish received, part 1)
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg_id: The id value for the message.

.. zeek:id:: mqtt_pubrel
   :source-code: base/protocols/mqtt/main.zeek 268 277

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_id: :zeek:type:`count`)

   Generated for MQTT publish release messages (QoS 2 publish received, part 2)
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg_id: The id value for the message.

.. zeek:id:: mqtt_pubcomp
   :source-code: base/bif/plugins/Zeek_MQTT.events.bif.zeek 67 67

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_id: :zeek:type:`count`)

   Generated for MQTT publish complete messages (QoS 2 publish received, part 3)
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg_id: The id value for the message.

.. zeek:id:: mqtt_subscribe
   :source-code: base/protocols/mqtt/main.zeek 306 318

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg_id: :zeek:type:`count`, topics: :zeek:type:`string_vec`, requested_qos: :zeek:type:`index_vec`)

   Generated for MQTT subscribe messages
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg_id: The id value for the message.
   

   :param topics: The topics being subscribed to
   

   :param requested_qos: The desired QoS option associated with each topic.

.. zeek:id:: mqtt_suback
   :source-code: base/protocols/mqtt/main.zeek 320 333

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg_id: :zeek:type:`count`, granted_qos: :zeek:type:`count`)

   Generated for MQTT subscribe messages
   

   :param c: The connection
   

   :param is_orig: Direction in which the message was sent
   

   :param msg_id: The id value for the message.

.. zeek:id:: mqtt_unsubscribe
   :source-code: base/protocols/mqtt/main.zeek 335 346

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg_id: :zeek:type:`count`, topics: :zeek:type:`string_vec`)

   Generated for MQTT unsubscribe messages sent by the client
   

   :param c: The connection
   

   :param msg_id: The id value for the message.
   

   :param topics: The topics being unsubscribed from

.. zeek:id:: mqtt_unsuback
   :source-code: base/protocols/mqtt/main.zeek 348 360

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg_id: :zeek:type:`count`)

   Generated for MQTT unsubscribe acknowledgements sent by the server
   

   :param c: The connection
   

   :param msg_id: The id value for the message.

.. zeek:id:: mqtt_pingreq
   :source-code: base/bif/plugins/Zeek_MQTT.events.bif.zeek 115 115

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for MQTT ping requests sent by the client.
   

   :param c: The connection

.. zeek:id:: mqtt_pingresp
   :source-code: base/bif/plugins/Zeek_MQTT.events.bif.zeek 121 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for MQTT ping responses sent by the server.
   

   :param c: The connection

.. zeek:id:: mqtt_disconnect
   :source-code: base/bif/plugins/Zeek_MQTT.events.bif.zeek 127 127

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for MQTT disconnect messages sent by the client when it is disconnecting cleanly.
   

   :param c: The connection

.. _plugin-zeek-mysql:

Zeek::MySQL
-----------

MySQL analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_MYSQL`

Events
++++++

.. zeek:id:: mysql_command_request
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 16 16

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, command: :zeek:type:`count`, arg: :zeek:type:`string`)

   Generated for a command request from a MySQL client.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param command: The numerical code of the command issued.
   

   :param arg: The argument for the command (empty string if not provided).
   
   .. zeek:see:: mysql_error mysql_ok mysql_server_version mysql_handshake

.. zeek:id:: mysql_error
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`, msg: :zeek:type:`string`)

   Generated for an unsuccessful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param code: The error code.
   

   :param msg: Any extra details about the error (empty string if not provided).
   
   .. zeek:see:: mysql_command_request mysql_ok mysql_server_version mysql_handshake

.. zeek:id:: mysql_ok
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 44 44

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, affected_rows: :zeek:type:`count`)

   Generated for a successful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param affected_rows: The number of rows that were affected.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_eof
   :source-code: base/protocols/mysql/main.zeek 115 132

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_intermediate: :zeek:type:`bool`)

   Generated for a MySQL EOF packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param is_intermediate: True if this is an EOF packet between the column definition and the rows, false if a final EOF.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_result_row
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 70 70

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, row: :zeek:type:`string_vec`)

   Generated for each MySQL ResultsetRow response packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param row: The result row data.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake mysql_ok

.. zeek:id:: mysql_server_version
   :source-code: policy/protocols/mysql/software.zeek 14 20

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ver: :zeek:type:`string`)

   Generated for the initial server handshake packet, which includes the MySQL server version.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param ver: The server version string.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_handshake

.. zeek:id:: mysql_handshake
   :source-code: base/protocols/mysql/main.zeek 52 65

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, username: :zeek:type:`string`)

   Generated for a client handshake response packet, which includes the username the client is attempting
   to connect as.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param username: The username supplied by the client
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_server_version

.. _plugin-zeek-ncp:

Zeek::NCP
---------

NCP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_NCP`

:zeek:enum:`Analyzer::ANALYZER_NCP`

Options/Constants
+++++++++++++++++

.. zeek:id:: NCP::max_frame_size
   :source-code: base/init-bare.zeek 5471 5471

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``65536``

   The maximum number of bytes to allocate when parsing NCP frames.

Events
++++++

.. zeek:id:: ncp_request
   :source-code: base/bif/plugins/Zeek_NCP.events.bif.zeek 23 23

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, frame_type: :zeek:type:`count`, length: :zeek:type:`count`, func: :zeek:type:`count`)

   Generated for NCP requests (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :param c: The connection.
   

   :param frame_type: The frame type, as specified by the protocol.
   

   :param length: The length of the request body, excluding the frame header.
   

   :param func: The requested function, as specified by the protocol.
   
   .. zeek:see:: ncp_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: ncp_reply
   :source-code: base/bif/plugins/Zeek_NCP.events.bif.zeek 49 49

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, frame_type: :zeek:type:`count`, length: :zeek:type:`count`, req_frame: :zeek:type:`count`, req_func: :zeek:type:`count`, completion_code: :zeek:type:`count`)

   Generated for NCP replies (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :param c: The connection.
   

   :param frame_type: The frame type, as specified by the protocol.
   

   :param length: The length of the request body, excluding the frame header.
   

   :param req_frame: The frame type from the corresponding request.
   

   :param req_func: The function code from the corresponding request.
   

   :param completion_code: The reply's completion code, as specified by the protocol.
   
   .. zeek:see:: ncp_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. _plugin-zeek-netbios:

Zeek::NetBIOS
-------------

NetBIOS analyzer support

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_NETBIOSSSN`

:zeek:enum:`Analyzer::ANALYZER_NETBIOSSSN`

Events
++++++

.. zeek:id:: netbios_session_message
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_type: :zeek:type:`count`, data_len: :zeek:type:`count`)

   Generated for all NetBIOS SSN and DGM messages. Zeek's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param is_orig:  True if the message was sent by the originator of the connection.
   

   :param msg_type: The general type of message, as defined in Section 4.3.1 of
             :rfc:`1002`.
   

   :param data_len: The length of the message's payload.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp  decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_request
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 63 63

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *session request*. Zeek's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_accepted
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *positive session response*. Zeek's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see::  netbios_session_keepalive netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_rejected
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 121 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *negative session response*. Zeek's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_raw_message
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 157 157

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *session message* that are not
   carrying an SMB payload.
   
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param is_orig: True if the message was sent by the originator of the connection.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header (i.e., the ``user_data``).
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event. In fact, it's probably an odd event
      to have to begin with.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_ret_arg_resp
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 188 188

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *retarget response*. Zeek's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_request decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_keepalive
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 217 217

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *keep-alive*. Zeek's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Functions
+++++++++

.. zeek:id:: decode_netbios_name
   :source-code: base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek 16 16

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`string`

   Decode a NetBIOS name.  See https://jeffpar.github.io/kbarchive/kb/194/Q194203/.
   

   :param name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
   

   :returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAM"``.  An empty
            string is returned if the argument is not a valid NetBIOS encoding
            (though an encoding that would decode to something that includes
            only null-bytes or space-characters also yields an empty string).
   
   .. zeek:see:: decode_netbios_name_type

.. zeek:id:: decode_netbios_name_type
   :source-code: base/bif/plugins/Zeek_NetBIOS.functions.bif.zeek 27 27

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`count`

   Converts a NetBIOS name type to its corresponding numeric value.
   See https://en.wikipedia.org/wiki/NetBIOS#NetBIOS_Suffixes.
   

   :param name: An encoded NetBIOS name.
   

   :returns: The numeric value of *name* or 256 if it's not a valid encoding.
   
   .. zeek:see:: decode_netbios_name

.. _plugin-zeek-ntlm:

Zeek::NTLM
----------

NTLM analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_NTLM`

Types
+++++

.. zeek:type:: NTLM::Negotiate
   :source-code: base/init-bare.zeek 3049 3058

   :Type: :zeek:type:`record`

      flags: :zeek:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The domain name of the client, if known

      workstation: :zeek:type:`string` :zeek:attr:`&optional`
         The machine name of the client, if known

      version: :zeek:type:`NTLM::Version` :zeek:attr:`&optional`
         The Windows version information, if supplied


.. zeek:type:: NTLM::Challenge
   :source-code: base/init-bare.zeek 3086 3100

   :Type: :zeek:type:`record`

      flags: :zeek:type:`NTLM::NegotiateFlags`
         The negotiate flags

      challenge: :zeek:type:`count`
         A 64-bit value that contains the NTLM challenge.

      target_name: :zeek:type:`string` :zeek:attr:`&optional`
         The server authentication realm. If the server is
         domain-joined, the name of the domain. Otherwise
         the server name. See flags.target_type_domain
         and flags.target_type_server

      version: :zeek:type:`NTLM::Version` :zeek:attr:`&optional`
         The Windows version information, if supplied

      target_info: :zeek:type:`NTLM::AVs` :zeek:attr:`&optional`
         Attribute-value pairs specified by the server


.. zeek:type:: NTLM::Authenticate
   :source-code: base/init-bare.zeek 3102 3117

   :Type: :zeek:type:`record`

      flags: :zeek:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The domain or computer name hosting the account

      user_name: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the user to be authenticated.

      workstation: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the computer to which the user was logged on.

      session_key: :zeek:type:`string` :zeek:attr:`&optional`
         The session key

      version: :zeek:type:`NTLM::Version` :zeek:attr:`&optional`
         The Windows version information, if supplied

      response: :zeek:type:`string` :zeek:attr:`&optional`
         The client's response for the challenge


.. zeek:type:: NTLM::NegotiateFlags
   :source-code: base/init-bare.zeek 2994 3047

   :Type: :zeek:type:`record`

      negotiate_56: :zeek:type:`bool`
         If set, requires 56-bit encryption

      negotiate_key_exch: :zeek:type:`bool`
         If set, requests an explicit key exchange

      negotiate_128: :zeek:type:`bool`
         If set, requests 128-bit session key negotiation

      negotiate_version: :zeek:type:`bool`
         If set, requests the protocol version number

      negotiate_target_info: :zeek:type:`bool`
         If set, indicates that the TargetInfo fields in the
         CHALLENGE_MESSAGE are populated

      request_non_nt_session_key: :zeek:type:`bool`
         If set, requests the usage of the LMOWF function

      negotiate_identify: :zeek:type:`bool`
         If set, requests and identify level token

      negotiate_extended_sessionsecurity: :zeek:type:`bool`
         If set, requests usage of NTLM v2 session security
         Note: NTLM v2 session security is actually NTLM v1

      target_type_server: :zeek:type:`bool`
         If set, TargetName must be a server name

      target_type_domain: :zeek:type:`bool`
         If set, TargetName must be a domain name

      negotiate_always_sign: :zeek:type:`bool`
         If set, requests the presence of a signature block
         on all messages

      negotiate_oem_workstation_supplied: :zeek:type:`bool`
         If set, the workstation name is provided

      negotiate_oem_domain_supplied: :zeek:type:`bool`
         If set, the domain name is provided

      negotiate_anonymous_connection: :zeek:type:`bool`
         If set, the connection should be anonymous

      negotiate_ntlm: :zeek:type:`bool`
         If set, requests usage of NTLM v1

      negotiate_lm_key: :zeek:type:`bool`
         If set, requests LAN Manager session key computation

      negotiate_datagram: :zeek:type:`bool`
         If set, requests connectionless authentication

      negotiate_seal: :zeek:type:`bool`
         If set, requests session key negotiation for message
         confidentiality

      negotiate_sign: :zeek:type:`bool`
         If set, requests session key negotiation for message
         signatures

      request_target: :zeek:type:`bool`
         If set, the TargetName field is present

      negotiate_oem: :zeek:type:`bool`
         If set, requests OEM character set encoding

      negotiate_unicode: :zeek:type:`bool`
         If set, requests Unicode character set encoding


.. zeek:type:: NTLM::Version
   :source-code: base/init-bare.zeek 2983 2992

   :Type: :zeek:type:`record`

      major: :zeek:type:`count`
         The major version of the Windows operating system in use

      minor: :zeek:type:`count`
         The minor version of the Windows operating system in use

      build: :zeek:type:`count`
         The build number of the Windows operating system in use

      ntlmssp: :zeek:type:`count`
         The current revision of NTLMSSP in use


.. zeek:type:: NTLM::AVs
   :source-code: base/init-bare.zeek 3060 3084

   :Type: :zeek:type:`record`

      nb_computer_name: :zeek:type:`string`
         The server's NetBIOS computer name

      nb_domain_name: :zeek:type:`string`
         The server's NetBIOS domain name

      dns_computer_name: :zeek:type:`string` :zeek:attr:`&optional`
         The FQDN of the computer

      dns_domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The FQDN of the domain

      dns_tree_name: :zeek:type:`string` :zeek:attr:`&optional`
         The FQDN of the forest

      constrained_auth: :zeek:type:`bool` :zeek:attr:`&optional`
         Indicates to the client that the account
         authentication is constrained

      timestamp: :zeek:type:`time` :zeek:attr:`&optional`
         The associated timestamp, if present

      single_host_id: :zeek:type:`count` :zeek:attr:`&optional`
         Indicates that the client is providing
         a machine ID created at computer startup to
         identify the calling machine

      target_name: :zeek:type:`string` :zeek:attr:`&optional`
         The SPN of the target server


Events
++++++

.. zeek:id:: ntlm_negotiate
   :source-code: base/protocols/ntlm/main.zeek 64 67

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, negotiate: :zeek:type:`NTLM::Negotiate`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *negotiate*.
   

   :param c: The connection.
   

   :param negotiate: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. zeek:see:: ntlm_challenge ntlm_authenticate

.. zeek:id:: ntlm_challenge
   :source-code: base/protocols/ntlm/main.zeek 69 83

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, challenge: :zeek:type:`NTLM::Challenge`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *challenge*.
   

   :param c: The connection.
   

   :param negotiate: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. zeek:see:: ntlm_negotiate ntlm_authenticate

.. zeek:id:: ntlm_authenticate
   :source-code: base/protocols/ntlm/main.zeek 85 95

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, request: :zeek:type:`NTLM::Authenticate`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *authenticate*.
   

   :param c: The connection.
   

   :param request: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. zeek:see:: ntlm_negotiate ntlm_challenge

.. _plugin-zeek-ntp:

Zeek::NTP
---------

NTP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_NTP`

Types
+++++

.. zeek:type:: NTP::StandardMessage
   :source-code: base/init-bare.zeek 5479 5532

   :Type: :zeek:type:`record`

      stratum: :zeek:type:`count`
         This value mainly identifies the type of server (primary server,
         secondary server, etc.). Possible values, as in :rfc:`5905`, are:
         
           * 0 -> unspecified or invalid
           * 1 -> primary server (e.g., equipped with a GPS receiver)
           * 2-15 -> secondary server (via NTP)
           * 16 -> unsynchronized
           * 17-255 -> reserved
         
         For stratum 0, a *kiss_code* can be given for debugging and
         monitoring.

      poll: :zeek:type:`interval`
         The maximum interval between successive messages.

      precision: :zeek:type:`interval`
         The precision of the system clock.

      root_delay: :zeek:type:`interval`
         Root delay. The total round-trip delay to the reference clock.

      root_disp: :zeek:type:`interval`
         Root Dispersion. The total dispersion to the reference clock.

      kiss_code: :zeek:type:`string` :zeek:attr:`&optional`
         For stratum 0, four-character ASCII string used for debugging and
         monitoring. Values are defined in :rfc:`1345`.

      ref_id: :zeek:type:`string` :zeek:attr:`&optional`
         Reference ID. For stratum 1, this is the ID assigned to the
         reference clock by IANA.
         For example: GOES, GPS, GAL, etc. (see :rfc:`5905`)

      ref_addr: :zeek:type:`addr` :zeek:attr:`&optional`
         Above stratum 1, when using IPv4, the IP address of the reference
         clock.  Note that the NTP protocol did not originally specify a
         large enough field to represent IPv6 addresses, so they use
         the first four bytes of the MD5 hash of the reference clock's
         IPv6 address (i.e. an IPv4 address here is not necessarily IPv4).

      ref_time: :zeek:type:`time`
         Reference timestamp. Time when the system clock was last set or
         correct.

      org_time: :zeek:type:`time`
         Origin timestamp. Time at the client when the request departed for
         the NTP server.

      rec_time: :zeek:type:`time`
         Receive timestamp. Time at the server when the request arrived from
         the NTP client.

      xmt_time: :zeek:type:`time`
         Transmit timestamp. Time at the server when the response departed

      key_id: :zeek:type:`count` :zeek:attr:`&optional`
         Key used to designate a secret MD5 key.

      digest: :zeek:type:`string` :zeek:attr:`&optional`
         MD5 hash computed over the key followed by the NTP packet header and
         extension fields.

      num_exts: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Number of extension fields (which are not currently parsed).

   NTP standard message as defined in :rfc:`5905` for modes 1-5
   This record contains the standard fields used by the NTP protocol
   for standard synchronization operations.

.. zeek:type:: NTP::ControlMessage
   :source-code: base/init-bare.zeek 5537 5571

   :Type: :zeek:type:`record`

      op_code: :zeek:type:`count`
         An integer specifying the command function. Values currently defined:
         
         * 1 read status command/response
         * 2 read variables command/response
         * 3 write variables command/response
         * 4 read clock variables command/response
         * 5 write clock variables command/response
         * 6 set trap address/port command/response
         * 7 trap response
         
         Other values are reserved.

      resp_bit: :zeek:type:`bool`
         The response bit. Set to zero for commands, one for responses.

      err_bit: :zeek:type:`bool`
         The error bit. Set to zero for normal response, one for error
         response.

      more_bit: :zeek:type:`bool`
         The more bit. Set to zero for last fragment, one for all others.

      sequence: :zeek:type:`count`
         The sequence number of the command or response.

      status: :zeek:type:`count`
         The current status of the system, peer or clock.

      association_id: :zeek:type:`count`
         A 16-bit integer identifying a valid association.

      data: :zeek:type:`string` :zeek:attr:`&optional`
         Message data for the command or response + Authenticator (optional).

      key_id: :zeek:type:`count` :zeek:attr:`&optional`
         This is an integer identifying the cryptographic
         key used to generate the message-authentication code.

      crypto_checksum: :zeek:type:`string` :zeek:attr:`&optional`
         This is a crypto-checksum computed by the encryption procedure.

   NTP control message as defined in :rfc:`1119` for mode=6
   This record contains the fields used by the NTP protocol
   for control operations.

.. zeek:type:: NTP::Mode7Message
   :source-code: base/init-bare.zeek 5580 5613

   :Type: :zeek:type:`record`

      req_code: :zeek:type:`count`
         An implementation-specific code which specifies the
         operation to be (which has been) performed and/or the
         format and semantics of the data included in the packet.

      auth_bit: :zeek:type:`bool`
         The authenticated bit. If set, this packet is authenticated.

      sequence: :zeek:type:`count`
         For a multipacket response, contains the sequence
         number of this packet.  0 is the first in the sequence,
         127 (or less) is the last.  The More Bit must be set in
         all packets but the last.

      implementation: :zeek:type:`count`
         The number of the implementation this request code
         is defined by.  An implementation number of zero is used
         for request codes/data formats which all implementations
         agree on.  Implementation number 255 is reserved (for
         extensions, in case we run out).

      err: :zeek:type:`count`
         Must be 0 for a request.  For a response, holds an error
         code relating to the request.  If nonzero, the operation
         requested wasn't performed.
         
           * 0 - no error
           * 1 - incompatible implementation number
           * 2 - unimplemented request code
           * 3 - format error (wrong data items, data size, packet size etc.)
           * 4 - no data available (e.g. request for details on unknown peer)
           * 5 - unknown
           * 6 - unknown
           * 7 - authentication failure (i.e. permission denied)

      data: :zeek:type:`string` :zeek:attr:`&optional`
         Rest of data

   NTP mode 7 message. Note that this is not defined in any RFC and is
   implementation dependent. We used the official implementation from the
   `NTP official project <https://www.ntp.org>`_.  A mode 7 packet is used
   exchanging data between an NTP server and a client for purposes other
   than time synchronization, e.g.  monitoring, statistics gathering and
   configuration.  For details see the documentation from the `NTP official
   project <https://www.ntp.org>`_, code v. ntp-4.2.8p13, in include/ntp_request.h.

.. zeek:type:: NTP::Message
   :source-code: base/init-bare.zeek 5618 5645

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`
         The NTP version number (1, 2, 3, 4).

      mode: :zeek:type:`count`
         The NTP mode being used. Possible values are:
         
           * 1 - symmetric active
           * 2 - symmetric passive
           * 3 - client
           * 4 - server
           * 5 - broadcast
           * 6 - NTP control message
           * 7 - reserved for private use

      std_msg: :zeek:type:`NTP::StandardMessage` :zeek:attr:`&optional`
         If mode 1-5, the standard fields for synchronization operations are
         here.  See :rfc:`5905`

      control_msg: :zeek:type:`NTP::ControlMessage` :zeek:attr:`&optional`
         If mode 6, the fields for control operations are here.
         See :rfc:`1119`

      mode7_msg: :zeek:type:`NTP::Mode7Message` :zeek:attr:`&optional`
         If mode 7, the fields for extra operations are here.
         Note that this is not defined in any RFC
         and is implementation dependent. We used the official implementation
         from the `NTP official project <https://www.ntp.org>`_.
         A mode 7 packet is used exchanging data between an NTP server
         and a client for purposes other than time synchronization, e.g.
         monitoring, statistics gathering and configuration.

   NTP message as defined in :rfc:`5905`.  Does include fields for mode 7,
   reserved for private use in :rfc:`5905`, but used in some implementation
   for commands such as "monlist".

Events
++++++

.. zeek:id:: ntp_message
   :source-code: base/bif/plugins/Zeek_NTP.events.bif.zeek 15 15

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`NTP::Message`)

   Generated for all NTP messages. Different from many other of Zeek's events,
   this one is generated for both client-side and server-side messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Network_Time_Protocol>`__ for
   more information about the NTP protocol.
   

   :param c: The connection record describing the corresponding UDP flow.
   

   :param is_orig: True if the message was sent by the originator.
   

   :param msg: The parsed NTP message.

.. _plugin-zeek-pia:

Zeek::PIA
---------

Analyzers implementing Dynamic Protocol

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_PIA_TCP`

:zeek:enum:`Analyzer::ANALYZER_PIA_UDP`

.. _plugin-zeek-pop3:

Zeek::POP3
----------

POP3 analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_POP3`

Options/Constants
+++++++++++++++++

.. zeek:id:: POP3::max_pending_commands
   :source-code: base/init-bare.zeek 2926 2926

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   How many commands a POP3 client may have pending
   before Zeek forcefully removes the oldest.
   
   Setting this value to 0 removes the limit.

.. zeek:id:: POP3::max_unknown_client_commands
   :source-code: base/init-bare.zeek 2932 2932

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   How many invalid commands a POP3 client may use
   before Zeek starts raising analyzer violations.
   
   Setting this value to 0 removes the limit.

Events
++++++

.. zeek:id:: pop3_request
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 25 25

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, command: :zeek:type:`string`, arg: :zeek:type:`string`)

   Generated for client-side commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param command: The command sent.
   

   :param arg: The argument to the command.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_reply
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 52 52

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, cmd: :zeek:type:`string`, msg: :zeek:type:`string`)

   Generated for server-side replies to commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param cmd: The success indicator sent by the server. This corresponds to the
        first token on the line sent, and should be either ``OK`` or ``ERR``.
   

   :param msg: The textual description the server sent along with *cmd*.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_request
      pop3_unexpected
   
   .. todo:: This event is receiving odd parameters, should unify.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_data
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 76 76

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for server-side multi-line responses on POP3 connections. POP3
   connections use multi-line responses to send bulk data, such as the actual
   mails. This event is generated once for each line that's part of such a
   response.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the data was sent by the originator of the TCP connection.
   

   :param data: The data sent.
   
   .. zeek:see:: pop3_login_failure pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_unexpected
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 100 100

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for errors encountered on POP3 sessions. If the POP3 analyzer
   finds state transitions that do not conform to the protocol specification,
   or other situations it can't handle, it raises this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the data was sent by the originator of the TCP connection.
   

   :param msg: A textual description of the situation.
   

   :param detail: The input that triggered the event.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply pop3_request
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_starttls
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 120 120

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a POP3 connection goes encrypted. While POP3 is by default a
   clear-text protocol, extensions exist to switch to encryption. This event is
   generated if that happens and the analyzer then stops processing the
   connection.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_request pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_login_success
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 144 144

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for successful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: Always false.
   

   :param user: The user name used for authentication. The event is only generated if
         a non-empty user name was used.
   

   :param password: The password used for authentication.
   
   .. zeek:see:: pop3_data pop3_login_failure pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pop3_login_failure
   :source-code: base/bif/plugins/Zeek_POP3.events.bif.zeek 168 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for unsuccessful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :param c: The connection.
   

   :param is_orig: Always false.
   

   :param user: The user name attempted for authentication. The event is only
         generated if a non-empty user name was used.
   

   :param password: The password attempted for authentication.
   
   .. zeek:see:: pop3_data pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. _plugin-zeek-quic:

Zeek::QUIC
----------

QUIC analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_QUIC`

Events
++++++

.. zeek:id:: QUIC::initial_packet
   :source-code: base/protocols/quic/main.zeek 134 138

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, dcid: :zeek:type:`string`, scid: :zeek:type:`string`)

   Generated for a QUIC Initial packet.
   

   :param c: The connection.
   

   :param is_orig: True if the packet is from the the connection's originator.
   

   :param version: The Version field.
   

   :param dcid: The Destination Connection ID field.
   

   :param scid: The Source Connection ID field.
   

.. zeek:id:: QUIC::retry_packet
   :source-code: base/protocols/quic/main.zeek 153 163

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, dcid: :zeek:type:`string`, scid: :zeek:type:`string`, retry_token: :zeek:type:`string`, retry_integrity_tag: :zeek:type:`string`)

   Generated for a QUIC Retry packet.
   

   :param c: The connection.
   

   :param is_orig: True if the packet is from the the connection's originator.
   

   :param version: The Version field.
   

   :param dcid: The Destination Connection ID field.
   

   :param scid: The Source Connection ID field.
   

   :param retry_token: The Retry Token field.
   

   :param integrity_tag: The Retry Integrity Tag field.

.. zeek:id:: QUIC::handshake_packet
   :source-code: base/protocols/quic/main.zeek 140 144

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, dcid: :zeek:type:`string`, scid: :zeek:type:`string`)

   Generated for a QUIC Handshake packet.
   

   :param c: The connection.
   

   :param is_orig: True if the packet is from the the connection's originator.
   

   :param version: The Version field.
   

   :param dcid: The Destination Connection ID field.
   

   :param scid: The Source Connection ID field.

.. zeek:id:: QUIC::zero_rtt_packet
   :source-code: base/protocols/quic/main.zeek 146 150

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, dcid: :zeek:type:`string`, scid: :zeek:type:`string`)

   Generated for a QUIC 0-RTT packet.
   

   :param c: The connection.
   

   :param is_orig: True if the packet is from the the connection's originator.
   

   :param version: The Version field.
   

   :param dcid: The Destination Connection ID field.
   

   :param scid: The Source Connection ID field.

.. zeek:id:: QUIC::connection_close_frame
   :source-code: base/protocols/quic/main.zeek 180 190

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, dcid: :zeek:type:`string`, scid: :zeek:type:`string`, error_code: :zeek:type:`count`, reason_phrase: :zeek:type:`string`)

   Generated for a QUIC CONNECTION_CLOSE frame.
   

   :param c: The connection.
   

   :param is_orig: True if the packet is from the the connection's originator.
   

   :param version: The Version field.
   

   :param dcid: The Destination Connection ID field.
   

   :param scid: The Source Connection ID field.
   

   :param error_code: Count indicating the reason for closing this connection.
   

   :param reason_phrase: Additional diagnostic information for the closure.
   
   .. note:: Packets with CONNECTION_CLOSE frames are usually encrypted after connection establishment and not visible to Zeek.

.. zeek:id:: QUIC::unhandled_version
   :source-code: base/protocols/quic/main.zeek 166 176

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, dcid: :zeek:type:`string`, scid: :zeek:type:`string`)

   Generated for an unrecognized QUIC version.
   

   :param c: The connection.
   

   :param is_orig: True if the packet is from the the connection's originator.
   

   :param version: The Version field.
   

   :param dcid: The Destination Connection ID field.
   

   :param scid: The Source Connection ID field.

.. _plugin-zeek-radius:

Zeek::RADIUS
------------

RADIUS analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_RADIUS`

Types
+++++

.. zeek:type:: RADIUS::AttributeList
   :source-code: base/init-bare.zeek 4691 4691

   :Type: :zeek:type:`vector` of :zeek:type:`string`


.. zeek:type:: RADIUS::Attributes
   :source-code: base/init-bare.zeek 4692 4692

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`RADIUS::AttributeList`


.. zeek:type:: RADIUS::Message
   :source-code: base/init-bare.zeek 4694 4703

   :Type: :zeek:type:`record`

      code: :zeek:type:`count`
         The type of message (Access-Request, Access-Accept, etc.).

      trans_id: :zeek:type:`count`
         The transaction ID.

      authenticator: :zeek:type:`string`
         The "authenticator" string.

      attributes: :zeek:type:`RADIUS::Attributes` :zeek:attr:`&optional`
         Any attributes.


Events
++++++

.. zeek:id:: radius_message
   :source-code: base/bif/plugins/Zeek_RADIUS.events.bif.zeek 13 13

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`RADIUS::Message`)

   Generated for RADIUS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :param c: The connection.
   

   :param result: A record containing fields parsed from a RADIUS packet.
   

.. zeek:id:: radius_attribute
   :source-code: base/bif/plugins/Zeek_RADIUS.events.bif.zeek 27 27

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, attr_type: :zeek:type:`count`, value: :zeek:type:`string`)

   Generated for each RADIUS attribute.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :param c: The connection.
   

   :param attr_type: The value of the code field (1 == User-Name, 2 == User-Password, etc.).
   

   :param value: The data/value bound to the attribute.
   

.. _plugin-zeek-rdp:

Zeek::RDP
---------

RDP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_RDP`

:zeek:enum:`Analyzer::ANALYZER_RDPEUDP`

Types
+++++

.. zeek:type:: RDP::EarlyCapabilityFlags
   :source-code: base/init-bare.zeek 4708 4718

   :Type: :zeek:type:`record`

      support_err_info_pdu: :zeek:type:`bool`

      want_32bpp_session: :zeek:type:`bool`

      support_statusinfo_pdu: :zeek:type:`bool`

      strong_asymmetric_keys: :zeek:type:`bool`

      support_monitor_layout_pdu: :zeek:type:`bool`

      support_netchar_autodetect: :zeek:type:`bool`

      support_dynvc_gfx_protocol: :zeek:type:`bool`

      support_dynamic_time_zone: :zeek:type:`bool`

      support_heartbeat_pdu: :zeek:type:`bool`


.. zeek:type:: RDP::ClientCoreData
   :source-code: base/init-bare.zeek 4720 4741

   :Type: :zeek:type:`record`

      version_major: :zeek:type:`count`

      version_minor: :zeek:type:`count`

      desktop_width: :zeek:type:`count`

      desktop_height: :zeek:type:`count`

      color_depth: :zeek:type:`count`

      sas_sequence: :zeek:type:`count`

      keyboard_layout: :zeek:type:`count`

      client_build: :zeek:type:`count`

      client_name: :zeek:type:`string`

      keyboard_type: :zeek:type:`count`

      keyboard_sub: :zeek:type:`count`

      keyboard_function_key: :zeek:type:`count`

      ime_file_name: :zeek:type:`string`

      post_beta2_color_depth: :zeek:type:`count` :zeek:attr:`&optional`

      client_product_id: :zeek:type:`count` :zeek:attr:`&optional`

      serial_number: :zeek:type:`count` :zeek:attr:`&optional`

      high_color_depth: :zeek:type:`count` :zeek:attr:`&optional`

      supported_color_depths: :zeek:type:`count` :zeek:attr:`&optional`

      ec_flags: :zeek:type:`RDP::EarlyCapabilityFlags` :zeek:attr:`&optional`

      dig_product_id: :zeek:type:`string` :zeek:attr:`&optional`


.. zeek:type:: RDP::ClientSecurityData
   :source-code: base/init-bare.zeek 4745 4757

   :Type: :zeek:type:`record`

      encryption_methods: :zeek:type:`count`
         Cryptographic encryption methods supported by the client and used in
         conjunction with Standard RDP Security.  Known flags:
         
         - 0x00000001: support for 40-bit session encryption keys
         - 0x00000002: support for 128-bit session encryption keys
         - 0x00000008: support for 56-bit session encryption keys
         - 0x00000010: support for FIPS compliant encryption and MAC methods

      ext_encryption_methods: :zeek:type:`count`
         Only used in French locale and designates the encryption method.  If
         non-zero, then encryption_methods should be set to 0.

   The TS_UD_CS_SEC data block contains security-related information used
   to advertise client cryptographic support.

.. zeek:type:: RDP::ClientClusterData
   :source-code: base/init-bare.zeek 4793 4812

   :Type: :zeek:type:`record`

      flags: :zeek:type:`count`
         Cluster information flags.

      redir_session_id: :zeek:type:`count`
         If the *redir_sessionid_field_valid* flag is set, this field
         contains a valid session identifier to which the client requests
         to connect.

      redir_supported: :zeek:type:`bool`
         The client can receive server session redirection packets.
         If this flag is set, the *svr_session_redir_version_mask*
         field MUST contain the server session redirection version that
         the client supports.

      svr_session_redir_version_mask: :zeek:type:`count`
         The server session redirection version that the client supports.

      redir_sessionid_field_valid: :zeek:type:`bool`
         Whether the *redir_session_id* field identifies a session on
         the server to associate with the connection.

      redir_smartcard: :zeek:type:`bool`
         The client logged on with a smart card.

   The TS_UD_CS_CLUSTER data block is sent by the client to the server
   either to advertise that it can support the Server Redirection PDUs
   or to request a connection to a given session identifier.

.. zeek:type:: RDP::ClientChannelList
   :source-code: base/init-bare.zeek 4815 4815

   :Type: :zeek:type:`vector` of :zeek:type:`RDP::ClientChannelDef`

   The list of channels requested by the client.

.. zeek:type:: RDP::ClientChannelDef
   :source-code: base/init-bare.zeek 4760 4788

   :Type: :zeek:type:`record`

      name: :zeek:type:`string`
         A unique name for the channel

      options: :zeek:type:`count`
         Channel Def raw options as count

      initialized: :zeek:type:`bool`
         Absence of this flag indicates that this channel is
         a placeholder and that the server MUST NOT set it up.

      encrypt_rdp: :zeek:type:`bool`
         Unused, must be ignored by the server.

      encrypt_sc: :zeek:type:`bool`
         Unused, must be ignored by the server.

      encrypt_cs: :zeek:type:`bool`
         Unused, must be ignored by the server.

      pri_high: :zeek:type:`bool`
         Channel data must be sent with high MCS priority.

      pri_med: :zeek:type:`bool`
         Channel data must be sent with medium MCS priority.

      pri_low: :zeek:type:`bool`
         Channel data must be sent with low MCS priority.

      compress_rdp: :zeek:type:`bool`
         Virtual channel data must be compressed if RDP data is being compressed.

      compress: :zeek:type:`bool`
         Virtual channel data must be compressed.

      show_protocol: :zeek:type:`bool`
         Ignored by the server.

      persistent: :zeek:type:`bool`
         Channel must be persistent across remote control transactions.

   Name and flags for a single channel requested by the client.

Events
++++++

.. zeek:id:: rdpeudp_syn
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 7 7

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for RDPEUDP SYN UDP Datagram
   

   :param c: The connection record for the underlying transport-layer session/flow.

.. zeek:id:: rdpeudp_synack
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 13 13

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for RDPEUDP SYNACK UDP Datagram
   

   :param c: The connection record for the underlying transport-layer session/flow.

.. zeek:id:: rdpeudp_established
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`)

   Generated when RDPEUDP connections are established (both sides SYN)
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param version: Whether the connection is RDPEUDP1 or RDPEUDP2

.. zeek:id:: rdpeudp_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated when for data messages exchanged after a RDPEUDP connection establishes
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param is_orig: Whether the data was sent by the originator or responder of the connection.
   

   :param version: Whether the connection is RDPEUDP1 or RDPEUDP2
   

   :param data: The payload of the packet. This is probably very non-performant.

.. zeek:id:: rdp_native_encrypted_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 43 43

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, len: :zeek:type:`count`)

   Generated for each packet after RDP native encryption begins
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param orig: True if the packet was sent by the originator of the connection.
   

   :param len: The length of the encrypted data.

.. zeek:id:: rdp_connect_request
   :source-code: base/protocols/rdp/main.zeek 165 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cookie: :zeek:type:`string`, flags: :zeek:type:`count`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cookie: :zeek:type:`string`)

   Generated for X.224 client requests.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param cookie: The cookie included in the request.
   

   :param flags: The flags set by the client.

.. zeek:id:: rdp_negotiation_response
   :source-code: base/protocols/rdp/main.zeek 172 177

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`, flags: :zeek:type:`count`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`)

   Generated for RDP Negotiation Response messages.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param security_protocol: The security protocol selected by the server.
   

   :param flags: The flags set by the server.

.. zeek:id:: rdp_negotiation_failure
   :source-code: base/protocols/rdp/main.zeek 179 184

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, failure_code: :zeek:type:`count`, flags: :zeek:type:`count`)
   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, failure_code: :zeek:type:`count`)

   Generated for RDP Negotiation Failure messages.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param failure_code: The failure code sent by the server.
   

   :param flags: The flags set by the server.

.. zeek:id:: rdp_client_core_data
   :source-code: base/protocols/rdp/main.zeek 186 212

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientCoreData`)

   Generated for MCS client requests.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param data: The data contained in the client core data structure.

.. zeek:id:: rdp_client_security_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 95 95

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientSecurityData`)

   Generated for client security data packets.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param data: The data contained in the client security data structure.

.. zeek:id:: rdp_client_network_data
   :source-code: base/protocols/rdp/main.zeek 214 227

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, channels: :zeek:type:`RDP::ClientChannelList`)

   Generated for Client Network Data (TS_UD_CS_NET) packets
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param channels: The channels that were requested

.. zeek:id:: rdp_client_cluster_data
   :source-code: base/bif/plugins/Zeek_RDP.events.bif.zeek 111 111

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, data: :zeek:type:`RDP::ClientClusterData`)

   Generated for client cluster data packets.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param data: The data contained in the client security data structure.

.. zeek:id:: rdp_gcc_server_create_response
   :source-code: base/protocols/rdp/main.zeek 229 234

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`count`)

   Generated for MCS server responses.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param result: The 8-bit integer representing the GCC Conference Create Response result.

.. zeek:id:: rdp_server_security
   :source-code: base/protocols/rdp/main.zeek 236 242

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, encryption_method: :zeek:type:`count`, encryption_level: :zeek:type:`count`)

   Generated for MCS server responses.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param encryption_method: The 32-bit integer representing the encryption method used in the connection.
   

   :param encryption_level: The 32-bit integer representing the encryption level used in the connection.

.. zeek:id:: rdp_server_certificate
   :source-code: base/protocols/rdp/main.zeek 244 256

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cert_type: :zeek:type:`count`, permanently_issued: :zeek:type:`bool`)

   Generated for a server certificate section.  If multiple X.509 
   certificates are included in chain, this event will still
   only be generated a single time.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param cert_type: Indicates the type of certificate.
   

   :param permanently_issued: Value will be true is the certificate(s) is permanent on the server.

.. zeek:id:: rdp_begin_encryption
   :source-code: base/protocols/rdp/main.zeek 258 268

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, security_protocol: :zeek:type:`count`)

   Generated when an RDP session becomes encrypted.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param security_protocol: The security protocol being used for the session.

.. _plugin-zeek-rfb:

Zeek::RFB
---------

Parser for rfb (VNC) analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_RFB`

Events
++++++

.. zeek:id:: rfb_authentication_type
   :source-code: base/protocols/rfb/main.zeek 131 136

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, authtype: :zeek:type:`count`)

   Generated for RFB event authentication mechanism selection
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param authtype: the value of the chosen authentication mechanism

.. zeek:id:: rfb_auth_result
   :source-code: base/protocols/rfb/main.zeek 152 155

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, result: :zeek:type:`bool`)

   Generated for RFB event authentication result message
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param result: whether or not authentication was successful

.. zeek:id:: rfb_share_flag
   :source-code: base/protocols/rfb/main.zeek 157 160

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, flag: :zeek:type:`bool`)

   Generated for RFB event share flag messages
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param flag: whether or not the share flag was set

.. zeek:id:: rfb_client_version
   :source-code: base/protocols/rfb/main.zeek 117 122

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_version: :zeek:type:`string`, minor_version: :zeek:type:`string`)

   Generated for RFB event client banner message
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param version: of the client's rfb library

.. zeek:id:: rfb_server_version
   :source-code: base/protocols/rfb/main.zeek 124 129

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_version: :zeek:type:`string`, minor_version: :zeek:type:`string`)

   Generated for RFB event server banner message
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param version: of the server's rfb library

.. zeek:id:: rfb_server_parameters
   :source-code: base/bif/plugins/Zeek_RFB.events.bif.zeek 53 53

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, name: :zeek:type:`string`, width: :zeek:type:`count`, height: :zeek:type:`count`)

   Generated for RFB event server parameter message
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param name: name of the shared screen
   

   :param width: width of the shared screen
   

   :param height: height of the shared screen

.. _plugin-zeek-rpc:

Zeek::RPC
---------

Analyzers for RPC-based protocols

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_NFS`

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_RPC`

:zeek:enum:`Analyzer::ANALYZER_MOUNT`

:zeek:enum:`Analyzer::ANALYZER_NFS`

:zeek:enum:`Analyzer::ANALYZER_PORTMAPPER`

Events
++++++

.. zeek:id:: nfs_proc_null
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 25 25

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`)

   Generated for NFSv3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented  nfs_proc_read nfs_proc_readdir nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_getattr
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 54 54

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, fh: :zeek:type:`string`, attrs: :zeek:type:`NFS3::fattr_t`)

   Generated for NFSv3 request/reply dialogues of type *getattr*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param fh: TODO.
   

   :param attrs: The attributes returned in the reply. The values may not be valid if
         the request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_sattr
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 83 83

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::sattrargs_t`, rep: :zeek:type:`NFS3::sattr_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *sattr*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   

   :param rep: The attributes returned in the reply. The values may not be
        valid if the request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_lookup
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 112 112

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::lookup_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *lookup*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr  nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_read
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 141 141

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::readargs_t`, rep: :zeek:type:`NFS3::read_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *read*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_remove nfs_proc_rmdir
      nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
      NFS3::return_data NFS3::return_data_first_only NFS3::return_data_max
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_readlink
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 170 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, fh: :zeek:type:`string`, rep: :zeek:type:`NFS3::readlink_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *readlink*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param fh: The file handle passed in the request.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_symlink rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_symlink
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 199 199

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::symlinkargs_t`, rep: :zeek:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *symlink*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   

   :param rep: The attributes returned in the reply. The values may not be
        valid if the request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_link rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_link
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 228 228

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::linkargs_t`, rep: :zeek:type:`NFS3::link_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *link*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      nfs_proc_symlink rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_write
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 258 258

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::writeargs_t`, rep: :zeek:type:`NFS3::write_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *write*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir  nfs_reply_status rpc_call
      rpc_dialogue rpc_reply NFS3::return_data NFS3::return_data_first_only
      NFS3::return_data_max
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_create
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 287 287

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *create*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see::  nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_mkdir
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 316 316

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *mkdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_remove
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 345 345

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::delobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *remove*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink  nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_rmdir
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 374 374

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::diropargs_t`, rep: :zeek:type:`NFS3::delobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *rmdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove  nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_rename
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 403 403

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::renameopargs_t`, rep: :zeek:type:`NFS3::renameobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *rename*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rename nfs_proc_write
      nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_readdir
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 432 432

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, req: :zeek:type:`NFS3::readdirargs_t`, rep: :zeek:type:`NFS3::readdir_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *readdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req: TODO.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_proc_not_implemented
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 456 456

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`, proc: :zeek:type:`NFS3::proc_t`)

   Generated for NFSv3 request/reply dialogues of a type that Zeek's NFSv3
   analyzer does not implement.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param proc: The procedure called that Zeek does not implement.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_null nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
      nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: nfs_reply_status
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 475 475

   :Type: :zeek:type:`event` (n: :zeek:type:`connection`, info: :zeek:type:`NFS3::info_t`)

   Generated for each NFSv3 reply message received, reporting just the
   status included.
   

   :param n: The connection.
   

   :param info: Reports the status included in the reply.
   
   .. zeek:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_null
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 495 495

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`)

   Generated for Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   
   .. zeek:see:: pm_request_set pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_set
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 521 521

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, m: :zeek:type:`pm_mapping`, success: :zeek:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param m: The argument to the request.
   

   :param success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. zeek:see:: pm_request_null pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_unset
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 547 547

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, m: :zeek:type:`pm_mapping`, success: :zeek:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param m: The argument to the request.
   

   :param success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_getport
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 571 571

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, pr: :zeek:type:`pm_port_request`, p: :zeek:type:`port`)

   Generated for Portmapper request/reply dialogues of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param pr: The argument to the request.
   

   :param p: The port returned by the server.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_dump
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 594 594

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, m: :zeek:type:`pm_mappings`)

   Generated for Portmapper request/reply dialogues of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param m: The mappings returned by the server.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_callit pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_request_callit
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 619 619

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, call: :zeek:type:`pm_callit_request`, p: :zeek:type:`port`)

   Generated for Portmapper request/reply dialogues of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param call: The argument to the request.
   

   :param p: The port value returned by the call.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_null
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 643 643

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`)

   Generated for failed Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_set
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 669 669

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, m: :zeek:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :param m: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_unset
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 695 695

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, m: :zeek:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :param m: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_getport
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 720 720

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, pr: :zeek:type:`pm_port_request`)

   Generated for failed Portmapper requests of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :param pr: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_dump
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 744 744

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`)

   Generated for failed Portmapper requests of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_attempt_callit
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 770 770

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, status: :zeek:type:`rpc_status`, call: :zeek:type:`pm_callit_request`)

   Generated for failed Portmapper requests of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :param call: The argument to the original request.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: pm_bad_port
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 796 796

   :Type: :zeek:type:`event` (r: :zeek:type:`connection`, bad_p: :zeek:type:`count`)

   Generated for Portmapper requests or replies that include an invalid port
   number. Since ports are represented by unsigned 4-byte integers, they can
   stray outside the allowed range of 0--65535 by being >= 65536. If so, this
   event is generated.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :param r: The RPC connection.
   

   :param bad_p: The invalid port value.
   
   .. zeek:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_attempt_callit rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: rpc_dialogue
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 833 833

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, prog: :zeek:type:`count`, ver: :zeek:type:`count`, proc: :zeek:type:`count`, status: :zeek:type:`rpc_status`, start_time: :zeek:type:`time`, call_len: :zeek:type:`count`, reply_len: :zeek:type:`count`)

   Generated for RPC request/reply *pairs*. The RPC analyzer associates request
   and reply by their transaction identifiers and raises this event once both
   have been seen. If there's not a reply, this event will still be generated
   eventually on timeout. In that case, *status* will be set to
   :zeek:enum:`RPC_TIMEOUT`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :param c: The connection.
   

   :param prog: The remote program to call.
   

   :param ver: The version of the remote program to call.
   

   :param proc: The procedure of the remote program to call.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :param start_time: The time when the *call* was seen.
   

   :param call_len: The size of the *call_body* PDU.
   

   :param reply_len: The size of the *reply_body* PDU.
   
   .. zeek:see:: rpc_call rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: rpc_call
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 861 861

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, xid: :zeek:type:`count`, prog: :zeek:type:`count`, ver: :zeek:type:`count`, proc: :zeek:type:`count`, call_len: :zeek:type:`count`)

   Generated for RPC *call* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :param c: The connection.
   

   :param xid: The transaction identifier allowing to match requests with replies.
   

   :param prog: The remote program to call.
   

   :param ver: The version of the remote program to call.
   

   :param proc: The procedure of the remote program to call.
   

   :param call_len: The size of the *call_body* PDU.
   
   .. zeek:see::  rpc_dialogue rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: rpc_reply
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 886 886

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, xid: :zeek:type:`count`, status: :zeek:type:`rpc_status`, reply_len: :zeek:type:`count`)

   Generated for RPC *reply* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :param c: The connection.
   

   :param xid: The transaction identifier allowing to match requests with replies.
   

   :param status: The status of the reply, which should be one of the index values of
           :zeek:id:`RPC_status`.
   

   :param reply_len: The size of the *reply_body* PDU.
   
   .. zeek:see:: rpc_call rpc_dialogue  dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to add a
      call to :zeek:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. zeek:id:: mount_proc_null
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 905 905

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`)

   Generated for MOUNT3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_mnt
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 929 929

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, req: :zeek:type:`MOUNT3::dirmntargs_t`, rep: :zeek:type:`MOUNT3::mnt_reply_t`)

   Generated for MOUNT3 request/reply dialogues of type *mnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   

   :param rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_umnt
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 950 950

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, req: :zeek:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_umnt_all
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 971 971

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, req: :zeek:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt_all*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param req:  The arguments passed in the request.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_proc_not_implemented
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 990 990

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`, proc: :zeek:type:`MOUNT3::proc_t`)

   Generated for MOUNT3 request/reply dialogues of a type that Zeek's MOUNTv3
   analyzer does not implement.
   

   :param c: The RPC connection.
   

   :param info: Reports the status of the dialogue, along with some meta information.
   

   :param proc: The procedure called that Zeek does not implement.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: mount_reply_status
   :source-code: base/bif/plugins/Zeek_RPC.events.bif.zeek 1007 1007

   :Type: :zeek:type:`event` (n: :zeek:type:`connection`, info: :zeek:type:`MOUNT3::info_t`)

   Generated for each MOUNT3 reply message received, reporting just the
   status included.
   

   :param n: The connection.
   

   :param info: Reports the status included in the reply.
   
   .. zeek:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. _plugin-zeek-sip:

Zeek::SIP
---------

SIP analyzer UDP-only

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_SIP`

Events
++++++

.. zeek:id:: sip_request
   :source-code: base/protocols/sip/main.zeek 170 179

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, method: :zeek:type:`string`, original_URI: :zeek:type:`string`, version: :zeek:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` requests, used in Voice over IP (VoIP).
   
   This event is generated as soon as a request's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param method: The :abbr:`SIP (Session Initiation Protocol)` method extracted from the request (e.g., ``REGISTER``, ``NOTIFY``).
   

   :param original_URI: The unprocessed URI as specified in the request.
   

   :param version: The version number specified in the request (e.g., ``2.0``).
   
   .. zeek:see:: sip_reply sip_header sip_all_headers sip_begin_entity sip_end_entity

.. zeek:id:: sip_reply
   :source-code: base/protocols/sip/main.zeek 181 191

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`string`, code: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` replies, used in Voice over IP (VoIP).
   
   This event is generated as soon as a reply's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param version: The :abbr:`SIP (Session Initiation Protocol)` version in use.
   

   :param code: The response code.
   

   :param reason: Textual details for the response code.
   
   .. zeek:see:: sip_request sip_header sip_all_headers sip_begin_entity sip_end_entity

.. zeek:id:: sip_header
   :source-code: base/protocols/sip/main.zeek 193 273

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, name: :zeek:type:`string`, value: :zeek:type:`string`)

   Generated for each :abbr:`SIP (Session Initiation Protocol)` header.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the header came from the originator.
   

   :param name: Header name.
   

   :param value: Header value.
   
   .. zeek:see:: sip_request sip_reply sip_all_headers sip_begin_entity sip_end_entity

.. zeek:id:: sip_all_headers
   :source-code: base/bif/plugins/Zeek_SIP.events.bif.zeek 71 71

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, hlist: :zeek:type:`mime_header_list`)

   Generated once for all :abbr:`SIP (Session Initiation Protocol)` headers from the originator or responder.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the headers came from the originator.
   

   :param hlist: All the headers, and their values
   
   .. zeek:see:: sip_request sip_reply sip_header sip_begin_entity sip_end_entity

.. zeek:id:: sip_begin_entity
   :source-code: base/bif/plugins/Zeek_SIP.events.bif.zeek 86 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated at the beginning of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   This event is generated as soon as a message's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the message came from the originator.
   
   .. zeek:see:: sip_request sip_reply sip_header sip_all_headers sip_end_entity

.. zeek:id:: sip_end_entity
   :source-code: base/bif/plugins/Zeek_SIP.events.bif.zeek 99 99

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated at the end of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :param c: The connection.
   

   :param is_orig: Whether the message came from the originator.
   
   .. zeek:see:: sip_request sip_reply sip_header sip_all_headers sip_begin_entity

.. _plugin-zeek-smb:

Zeek::SMB
---------

SMB analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTS_SMB`

:zeek:enum:`Analyzer::ANALYZER_SMB`

Options/Constants
+++++++++++++++++

.. zeek:id:: SMB::pipe_filenames
   :source-code: base/init-bare.zeek 3152 3152

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/smb/consts.zeek`

      ``=``::

         spoolss, winreg, samr, srvsvc, netdfs, lsarpc, wkssvc, MsFteWds


   A set of file names used as named pipes over SMB. This
   only comes into play as a heuristic to identify named
   pipes when the drive mapping wasn't seen by Zeek.
   
   .. zeek:see:: smb_pipe_connect_heuristic

.. zeek:id:: SMB::max_pending_messages
   :source-code: base/init-bare.zeek 3162 3162

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   The maximum number of messages for which to retain state
   about offsets, fids, or tree ids within the parser. When
   the limit is reached, internal parser state is discarded
   and :zeek:see:`smb2_discarded_messages_state` raised.
   
   Setting this to zero will disable the functionality.
   
   .. zeek:see:: smb2_discarded_messages_state

.. zeek:id:: SMB::max_dce_rpc_analyzers
   :source-code: base/init-bare.zeek 3168 3168

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1000``

   Maximum number of DCE-RPC analyzers per connection
   before discarding them to avoid unbounded state growth.
   
   .. zeek:see:: smb_discarded_dce_rpc_analyzers

Types
+++++

.. zeek:type:: SMB1::NegotiateResponse
   :source-code: base/init-bare.zeek 3342 3351

   :Type: :zeek:type:`record`

      core: :zeek:type:`SMB1::NegotiateResponseCore` :zeek:attr:`&optional`
         If the server does not understand any of the dialect strings, or if
         PC NETWORK PROGRAM 1.0 is the chosen dialect.

      lanman: :zeek:type:`SMB1::NegotiateResponseLANMAN` :zeek:attr:`&optional`
         If the chosen dialect is greater than core up to and including
         LANMAN 2.1.

      ntlm: :zeek:type:`SMB1::NegotiateResponseNTLM` :zeek:attr:`&optional`
         If the chosen dialect is NT LM 0.12.


.. zeek:type:: SMB1::NegotiateResponseCore
   :source-code: base/init-bare.zeek 3271 3274

   :Type: :zeek:type:`record`

      dialect_index: :zeek:type:`count`
         Index of selected dialect


.. zeek:type:: SMB1::NegotiateResponseLANMAN
   :source-code: base/init-bare.zeek 3276 3302

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words (should be 13)

      dialect_index: :zeek:type:`count`
         Index of selected dialect

      security_mode: :zeek:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :zeek:type:`count`
         Max transmit buffer size (>= 1024)

      max_mpx_count: :zeek:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :zeek:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      raw_mode: :zeek:type:`SMB1::NegotiateRawMode`
         Raw mode

      session_key: :zeek:type:`count`
         Unique token identifying this session

      server_time: :zeek:type:`time`
         Current date and time at server

      encryption_key: :zeek:type:`string`
         The challenge encryption key

      primary_domain: :zeek:type:`string`
         The server's primary domain


.. zeek:type:: SMB1::NegotiateResponseNTLM
   :source-code: base/init-bare.zeek 3304 3340

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words (should be 17)

      dialect_index: :zeek:type:`count`
         Index of selected dialect

      security_mode: :zeek:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :zeek:type:`count`
         Max transmit buffer size

      max_mpx_count: :zeek:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :zeek:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      max_raw_size: :zeek:type:`count`
         Max raw buffer size

      session_key: :zeek:type:`count`
         Unique token identifying this session

      capabilities: :zeek:type:`SMB1::NegotiateCapabilities`
         Server capabilities

      server_time: :zeek:type:`time`
         Current date and time at server

      encryption_key: :zeek:type:`string` :zeek:attr:`&optional`
         The challenge encryption key.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      domain_name: :zeek:type:`string` :zeek:attr:`&optional`
         The name of the domain.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      guid: :zeek:type:`string` :zeek:attr:`&optional`
         A globally unique identifier assigned to the server.
         Present only for extended security (i.e. capabilities$extended_security = T)

      security_blob: :zeek:type:`string`
         Opaque security blob associated with the security package if capabilities$extended_security = T
         Otherwise, the challenge for challenge/response authentication.


.. zeek:type:: SMB1::NegotiateResponseSecurity
   :source-code: base/init-bare.zeek 3254 3269

   :Type: :zeek:type:`record`

      user_level: :zeek:type:`bool`
         This indicates whether the server, as a whole, is operating under
         Share Level or User Level security.

      challenge_response: :zeek:type:`bool`
         This indicates whether or not the server supports Challenge/Response
         authentication. If the bit is false, then plaintext passwords must
         be used.

      signatures_enabled: :zeek:type:`bool` :zeek:attr:`&optional`
         This indicates if the server is capable of performing MAC message
         signing. Note: Requires NT LM 0.12 or later.

      signatures_required: :zeek:type:`bool` :zeek:attr:`&optional`
         This indicates if the server is requiring the use of a MAC in each
         packet. If false, message signing is optional. Note: Requires NT LM 0.12
         or later.


.. zeek:type:: SMB1::NegotiateRawMode
   :source-code: base/init-bare.zeek 3203 3208

   :Type: :zeek:type:`record`

      read_raw: :zeek:type:`bool`
         Read raw supported

      write_raw: :zeek:type:`bool`
         Write raw supported


.. zeek:type:: SMB1::NegotiateCapabilities
   :source-code: base/init-bare.zeek 3210 3252

   :Type: :zeek:type:`record`

      raw_mode: :zeek:type:`bool`
         The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW

      mpx_mode: :zeek:type:`bool`
         The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX

      unicode: :zeek:type:`bool`
         The server supports unicode strings

      large_files: :zeek:type:`bool`
         The server supports large files with 64 bit offsets

      nt_smbs: :zeek:type:`bool`
         The server supports the SMBs particular to the NT LM 0.12 dialect. Implies nt_find.

      rpc_remote_apis: :zeek:type:`bool`
         The server supports remote admin API requests via DCE-RPC

      status32: :zeek:type:`bool`
         The server can respond with 32 bit status codes in Status.Status

      level_2_oplocks: :zeek:type:`bool`
         The server supports level 2 oplocks

      lock_and_read: :zeek:type:`bool`
         The server supports SMB_COM_LOCK_AND_READ

      nt_find: :zeek:type:`bool`
         Reserved

      dfs: :zeek:type:`bool`
         The server is DFS aware

      infolevel_passthru: :zeek:type:`bool`
         The server supports NT information level requests passing through

      large_readx: :zeek:type:`bool`
         The server supports large SMB_COM_READ_ANDX (up to 64k)

      large_writex: :zeek:type:`bool`
         The server supports large SMB_COM_WRITE_ANDX (up to 64k)

      unix: :zeek:type:`bool`
         The server supports CIFS Extensions for UNIX

      bulk_transfer: :zeek:type:`bool`
         The server supports SMB_BULK_READ, SMB_BULK_WRITE
         Note: No known implementations support this

      compressed_data: :zeek:type:`bool`
         The server supports compressed data transfer. Requires bulk_transfer.
         Note: No known implementations support this

      extended_security: :zeek:type:`bool`
         The server supports extended security exchanges


.. zeek:type:: SMB1::SessionSetupAndXRequest
   :source-code: base/init-bare.zeek 3369 3411

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words
            - 10 for pre NT LM 0.12
            - 12 for NT LM 0.12 with extended security
            - 13 for NT LM 0.12 without extended security

      max_buffer_size: :zeek:type:`count`
         Client maximum buffer size

      max_mpx_count: :zeek:type:`count`
         Actual maximum multiplexed pending request

      vc_number: :zeek:type:`count`
         Virtual circuit number. First VC == 0

      session_key: :zeek:type:`count`
         Session key (valid iff vc_number > 0)

      native_os: :zeek:type:`string`
         Client's native operating system

      native_lanman: :zeek:type:`string`
         Client's native LAN Manager type

      account_name: :zeek:type:`string` :zeek:attr:`&optional`
         Account name
         Note: not set for NT LM 0.12 with extended security

      account_password: :zeek:type:`string` :zeek:attr:`&optional`
         If challenge/response auth is not being used, this is the password.
         Otherwise, it's the response to the server's challenge.
         Note: Only set for pre NT LM 0.12

      primary_domain: :zeek:type:`string` :zeek:attr:`&optional`
         Client's primary domain, if known
         Note: not set for NT LM 0.12 with extended security

      case_insensitive_password: :zeek:type:`string` :zeek:attr:`&optional`
         Case insensitive password
         Note: only set for NT LM 0.12 without extended security

      case_sensitive_password: :zeek:type:`string` :zeek:attr:`&optional`
         Case sensitive password
         Note: only set for NT LM 0.12 without extended security

      security_blob: :zeek:type:`string` :zeek:attr:`&optional`
         Security blob
         Note: only set for NT LM 0.12 with extended security

      capabilities: :zeek:type:`SMB1::SessionSetupAndXCapabilities` :zeek:attr:`&optional`
         Client capabilities
         Note: only set for NT LM 0.12


.. zeek:type:: SMB1::SessionSetupAndXResponse
   :source-code: base/init-bare.zeek 3413 3426

   :Type: :zeek:type:`record`

      word_count: :zeek:type:`count`
         Count of parameter words (should be 3 for pre NT LM 0.12 and 4 for NT LM 0.12)

      is_guest: :zeek:type:`bool` :zeek:attr:`&optional`
         Were we logged in as a guest user?

      native_os: :zeek:type:`string` :zeek:attr:`&optional`
         Server's native operating system

      native_lanman: :zeek:type:`string` :zeek:attr:`&optional`
         Server's native LAN Manager type

      primary_domain: :zeek:type:`string` :zeek:attr:`&optional`
         Server's primary domain

      security_blob: :zeek:type:`string` :zeek:attr:`&optional`
         Security blob if NTLM


.. zeek:type:: SMB1::SessionSetupAndXCapabilities
   :source-code: base/init-bare.zeek 3353 3367

   :Type: :zeek:type:`record`

      unicode: :zeek:type:`bool`
         The client can use unicode strings

      large_files: :zeek:type:`bool`
         The client can deal with files having 64 bit offsets

      nt_smbs: :zeek:type:`bool`
         The client understands the SMBs introduced with NT LM 0.12
         Implies nt_find

      status32: :zeek:type:`bool`
         The client can receive 32 bit errors encoded in Status.Status

      level_2_oplocks: :zeek:type:`bool`
         The client understands Level II oplocks

      nt_find: :zeek:type:`bool`
         Reserved. Implied by nt_smbs.


.. zeek:type:: SMB1::Trans_Sec_Args
   :source-code: base/init-bare.zeek 3455 3472

   :Type: :zeek:type:`record`

      total_param_count: :zeek:type:`count`
         Total parameter count

      total_data_count: :zeek:type:`count`
         Total data count

      param_count: :zeek:type:`count`
         Parameter count

      param_offset: :zeek:type:`count`
         Parameter offset

      param_displacement: :zeek:type:`count`
         Parameter displacement

      data_count: :zeek:type:`count`
         Data count

      data_offset: :zeek:type:`count`
         Data offset

      data_displacement: :zeek:type:`count`
         Data displacement


.. zeek:type:: SMB1::Find_First2_Request_Args
   :source-code: base/init-bare.zeek 3495 3509

   :Type: :zeek:type:`record`

      search_attrs: :zeek:type:`count`
         File attributes to apply as a constraint to the search

      search_count: :zeek:type:`count`
         Max search results

      flags: :zeek:type:`count`
         Misc. flags for how the server should manage the transaction
         once results are returned

      info_level: :zeek:type:`count`
         How detailed the information returned in the results should be

      search_storage_type: :zeek:type:`count`
         Specify whether to search for directories or files

      file_name: :zeek:type:`string`
         The string to search for (note: may contain wildcards)


.. zeek:type:: SMB1::Find_First2_Response_Args
   :source-code: base/init-bare.zeek 3511 3521

   :Type: :zeek:type:`record`

      sid: :zeek:type:`count`
         The server generated search identifier

      search_count: :zeek:type:`count`
         Number of results returned by the search

      end_of_search: :zeek:type:`bool`
         Whether or not the search can be continued using
         the TRANS2_FIND_NEXT2 transaction

      ext_attr_error: :zeek:type:`string` :zeek:attr:`&optional`
         An extended attribute name that couldn't be retrieved


.. zeek:type:: SMB1::Trans2_Args
   :source-code: base/init-bare.zeek 3428 3453

   :Type: :zeek:type:`record`

      total_param_count: :zeek:type:`count`
         Total parameter count

      total_data_count: :zeek:type:`count`
         Total data count

      max_param_count: :zeek:type:`count`
         Max parameter count

      max_data_count: :zeek:type:`count`
         Max data count

      max_setup_count: :zeek:type:`count`
         Max setup count

      flags: :zeek:type:`count`
         Flags

      trans_timeout: :zeek:type:`count`
         Timeout

      param_count: :zeek:type:`count`
         Parameter count

      param_offset: :zeek:type:`count`
         Parameter offset

      data_count: :zeek:type:`count`
         Data count

      data_offset: :zeek:type:`count`
         Data offset

      setup_count: :zeek:type:`count`
         Setup count


.. zeek:type:: SMB1::Trans2_Sec_Args
   :source-code: base/init-bare.zeek 3474 3493

   :Type: :zeek:type:`record`

      total_param_count: :zeek:type:`count`
         Total parameter count

      total_data_count: :zeek:type:`count`
         Total data count

      param_count: :zeek:type:`count`
         Parameter count

      param_offset: :zeek:type:`count`
         Parameter offset

      param_displacement: :zeek:type:`count`
         Parameter displacement

      data_count: :zeek:type:`count`
         Data count

      data_offset: :zeek:type:`count`
         Data offset

      data_displacement: :zeek:type:`count`
         Data displacement

      FID: :zeek:type:`count`
         File ID


.. zeek:type:: SMB2::CloseResponse
   :source-code: base/init-bare.zeek 3636 3645

   :Type: :zeek:type:`record`

      alloc_size: :zeek:type:`count`
         The size, in bytes of the data that is allocated to the file.

      eof: :zeek:type:`count`
         The size, in bytes, of the file.

      times: :zeek:type:`SMB::MACTimes`
         The creation, last access, last write, and change times.

      attrs: :zeek:type:`SMB2::FileAttrs`
         The attributes of the file.

   The response to an SMB2 *close* request, which is used by the client to close an instance
   of a file that was opened previously.
   
   For more information, see MS-SMB2:2.2.16
   
   .. zeek:see:: smb2_close_response

.. zeek:type:: SMB2::CreateRequest
   :source-code: base/init-bare.zeek 3784 3791

   :Type: :zeek:type:`record`

      filename: :zeek:type:`string`
         Name of the file

      disposition: :zeek:type:`count`
         Defines the action the server MUST take if the file that is specified already exists.

      create_options: :zeek:type:`count`
         Specifies the options to be applied when creating or opening the file.

   The request sent by the client to request either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   
   .. zeek:see:: smb2_create_request

.. zeek:type:: SMB2::CreateResponse
   :source-code: base/init-bare.zeek 3799 3810

   :Type: :zeek:type:`record`

      file_id: :zeek:type:`SMB2::GUID`
         The SMB2 GUID for the file.

      size: :zeek:type:`count`
         Size of the file.

      times: :zeek:type:`SMB::MACTimes`
         Timestamps associated with the file in question.

      attrs: :zeek:type:`SMB2::FileAttrs`
         File attributes.

      create_action: :zeek:type:`count`
         The action taken in establishing the open.

   The response to an SMB2 *create_request* request, which is sent by the client to request
   either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.14
   
   .. zeek:see:: smb2_create_response

.. zeek:type:: SMB2::NegotiateResponse
   :source-code: base/init-bare.zeek 3711 3728

   :Type: :zeek:type:`record`

      dialect_revision: :zeek:type:`count`
         The preferred common SMB2 Protocol dialect number from the array that was sent in the SMB2
         NEGOTIATE Request.

      security_mode: :zeek:type:`count`
         The security mode field specifies whether SMB signing is enabled, required at the server, or both.

      server_guid: :zeek:type:`SMB2::GUID`
         A globally unique identifier that is generate by the server to uniquely identify the server.

      system_time: :zeek:type:`time`
         The system time of the SMB2 server when the SMB2 NEGOTIATE Request was processed.

      server_start_time: :zeek:type:`time`
         The SMB2 server start time.

      negotiate_context_count: :zeek:type:`count`
         The number of negotiate context values in SMB v. 3.1.1, otherwise reserved to 0.

      negotiate_context_values: :zeek:type:`SMB2::NegotiateContextValues`
         An array of context values in SMB v. 3.1.1.

   The response to an SMB2 *negotiate* request, which is used by the client to notify the server
   what dialects of the SMB2 protocol the client understands.
   
   For more information, see MS-SMB2:2.2.4
   
   .. zeek:see:: smb2_negotiate_response

.. zeek:type:: SMB2::SessionSetupRequest
   :source-code: base/init-bare.zeek 3736 3739

   :Type: :zeek:type:`record`

      security_mode: :zeek:type:`count`
         The security mode field specifies whether SMB signing is enabled or required at the client.

   The request sent by the client to request a new authenticated session
   within a new or existing SMB 2 Protocol transport connection to the server.
   
   For more information, see MS-SMB2:2.2.5
   
   .. zeek:see:: smb2_session_setup_request

.. zeek:type:: SMB2::SessionSetupResponse
   :source-code: base/init-bare.zeek 3763 3766

   :Type: :zeek:type:`record`

      flags: :zeek:type:`SMB2::SessionSetupFlags`
         Additional information about the session

   The response to an SMB2 *session_setup* request, which is sent by the client to request a
   new authenticated session within a new or existing SMB 2 Protocol transport connection
   to the server.
   
   For more information, see MS-SMB2:2.2.6
   
   .. zeek:see:: smb2_session_setup_response

.. zeek:type:: SMB2::SessionSetupFlags
   :source-code: base/init-bare.zeek 3747 3754

   :Type: :zeek:type:`record`

      guest: :zeek:type:`bool`
         If set, the client has been authenticated as a guest user.

      anonymous: :zeek:type:`bool`
         If set, the client has been authenticated as an anonymous user.

      encrypt: :zeek:type:`bool`
         If set, the server requires encryption of messages on this session.

   A flags field that indicates additional information about the session that's sent in the
   *session_setup* response.
   
   For more information, see MS-SMB2:2.2.6
   
   .. zeek:see:: smb2_session_setup_response

.. zeek:type:: SMB2::TreeConnectResponse
   :source-code: base/init-bare.zeek 3774 3777

   :Type: :zeek:type:`record`

      share_type: :zeek:type:`count`
         The type of share being accessed. Physical disk, named pipe, or printer.

   The response to an SMB2 *tree_connect* request, which is sent by the client to request
   access to a particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   
   .. zeek:see:: smb2_tree_connect_response

.. zeek:type:: SMB2::Transform_header
   :source-code: base/init-bare.zeek 3859 3870

   :Type: :zeek:type:`record`

      signature: :zeek:type:`string`
         The 16-byte signature of the encrypted message, generated by using Session.EncryptionKey.

      nonce: :zeek:type:`string`
         An implementation specific value assigned for every encrypted message.

      orig_msg_size: :zeek:type:`count`
         The size, in bytes, of the SMB2 message.

      flags: :zeek:type:`count`
         A flags field, interpreted in different ways depending of the SMB2 dialect.

      session_id: :zeek:type:`count`
         A value that uniquely identifies the established session for the command.

   An SMB2 transform header (for SMB 3.x dialects with encryption enabled).
   
   For more information, see MS-SMB2:2.2.41
   
   .. zeek:see:: smb2_transform_header smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. zeek:type:: SMB::MACTimes
   :source-code: base/init-bare.zeek 3128 3145

   :Type: :zeek:type:`record`

      modified: :zeek:type:`time` :zeek:attr:`&log`
         The time when data was last written to the file.

      modified_raw: :zeek:type:`count`
         Same as `modified` but in SMB's original `FILETIME` integer format.

      accessed: :zeek:type:`time` :zeek:attr:`&log`
         The time when the file was last accessed.

      accessed_raw: :zeek:type:`count`
         Same as `accessed` but in SMB's original `FILETIME` integer format.

      created: :zeek:type:`time` :zeek:attr:`&log`
         The time the file was created.

      created_raw: :zeek:type:`count`
         Same as `created` but in SMB's original `FILETIME` integer format.

      changed: :zeek:type:`time` :zeek:attr:`&log`
         The time when the file was last modified.

      changed_raw: :zeek:type:`count`
         Same as `changed` but in SMB's original `FILETIME` integer format.

   MAC times for a file.
   
   For more information, see MS-SMB2:2.2.16
   
   .. zeek:see:: smb1_nt_create_andx_response smb2_create_response

.. zeek:type:: SMB1::Header
   :source-code: base/init-bare.zeek 3192 3201

   :Type: :zeek:type:`record`

      command: :zeek:type:`count`
         The command number

      status: :zeek:type:`count`
         The status code

      flags: :zeek:type:`count`
         Flag set 1

      flags2: :zeek:type:`count`
         Flag set 2

      tid: :zeek:type:`count`
         Tree ID

      pid: :zeek:type:`count`
         Process ID

      uid: :zeek:type:`count`
         User ID

      mid: :zeek:type:`count`
         Multiplex ID

   An SMB1 header.
   
   .. zeek:see:: smb1_message smb1_empty_response smb1_error
      smb1_check_directory_request smb1_check_directory_response
      smb1_close_request smb1_create_directory_request
      smb1_create_directory_response smb1_echo_request
      smb1_echo_response smb1_negotiate_request
      smb1_negotiate_response smb1_nt_cancel_request
      smb1_nt_create_andx_request smb1_nt_create_andx_response
      smb1_query_information_request smb1_read_andx_request
      smb1_read_andx_response smb1_session_setup_andx_request
      smb1_session_setup_andx_response smb1_transaction_request
      smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request
      smb1_tree_connect_andx_request smb1_tree_connect_andx_response
      smb1_tree_disconnect smb1_write_andx_request
      smb1_write_andx_response

.. zeek:type:: SMB2::Header
   :source-code: base/init-bare.zeek 3540 3565

   :Type: :zeek:type:`record`

      credit_charge: :zeek:type:`count`
         The number of credits that this request consumes

      status: :zeek:type:`count`
         In a request, this is an indication to the server about the client's channel
         change. In a response, this is the status field

      command: :zeek:type:`count`
         The command code of the packet

      credits: :zeek:type:`count`
         The number of credits the client is requesting, or the number of credits
         granted to the client in a response.

      flags: :zeek:type:`count`
         A flags field, which indicates how to process the operation (e.g. asynchronously)

      message_id: :zeek:type:`count`
         A value that uniquely identifies the message request/response pair across all
         messages that are sent on the same transport protocol connection

      process_id: :zeek:type:`count`
         A value that uniquely identifies the process that generated the event.

      tree_id: :zeek:type:`count`
         A value that uniquely identifies the tree connect for the command.

      session_id: :zeek:type:`count`
         A value that uniquely identifies the established session for the command.

      signature: :zeek:type:`string`
         The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the ``flags``
         field.

   An SMB2 header.
   
   For more information, see MS-SMB2:2.2.1.1 and MS-SMB2:2.2.1.2
   
   .. zeek:see:: smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. zeek:type:: SMB2::GUID
   :source-code: base/init-bare.zeek 3573 3578

   :Type: :zeek:type:`record`

      persistent: :zeek:type:`count`
         A file handle that remains persistent when reconnected after a disconnect

      volatile: :zeek:type:`count`
         A file handle that can be changed when reconnected after a disconnect

   An SMB2 globally unique identifier which identifies a file.
   
   For more information, see MS-SMB2:2.2.14.1
   
   .. zeek:see:: smb2_close_request smb2_create_response smb2_read_request
      smb2_file_rename smb2_file_delete smb2_write_request

.. zeek:type:: SMB2::FileAttrs
   :source-code: base/init-bare.zeek 3585 3628

   :Type: :zeek:type:`record`

      read_only: :zeek:type:`bool`
         The file is read only. Applications can read the file but cannot
         write to it or delete it.

      hidden: :zeek:type:`bool`
         The file is hidden. It is not to be included in an ordinary directory listing.

      system: :zeek:type:`bool`
         The file is part of or is used exclusively by the operating system.

      directory: :zeek:type:`bool`
         The file is a directory.

      archive: :zeek:type:`bool`
         The file has not been archived since it was last modified. Applications use
         this attribute to mark files for backup or removal.

      normal: :zeek:type:`bool`
         The file has no other attributes set. This attribute is valid only if used alone.

      temporary: :zeek:type:`bool`
         The file is temporary. This is a hint to the cache manager that it does not need
         to flush the file to backing storage.

      sparse_file: :zeek:type:`bool`
         A file that is a sparse file.

      reparse_point: :zeek:type:`bool`
         A file or directory that has an associated reparse point.

      compressed: :zeek:type:`bool`
         The file or directory is compressed. For a file, this means that all of the data
         in the file is compressed. For a directory, this means that compression is the
         default for newly created files and subdirectories.

      offline: :zeek:type:`bool`
         The data in this file is not available immediately. This attribute indicates that
         the file data is physically moved to offline storage. This attribute is used by
         Remote Storage, which is hierarchical storage management software.

      not_content_indexed: :zeek:type:`bool`
         A file or directory that is not indexed by the content indexing service.

      encrypted: :zeek:type:`bool`
         A file or directory that is encrypted. For a file, all data streams in the file
         are encrypted. For a directory, encryption is the default for newly created files
         and subdirectories.

      integrity_stream: :zeek:type:`bool`
         A file or directory that is configured with integrity support. For a file, all
         data streams in the file have integrity support. For a directory, integrity support
         is the default for newly created files and subdirectories, unless the caller
         specifies otherwise.

      no_scrub_data: :zeek:type:`bool`
         A file or directory that is configured to be excluded from the data integrity scan.

   A series of boolean flags describing basic and extended file attributes for SMB2.
   
   For more information, see MS-CIFS:2.2.1.2.3 and MS-FSCC:2.6
   
   .. zeek:see:: smb2_create_response

.. zeek:type:: SMB2::Fscontrol
   :source-code: base/init-bare.zeek 3816 3829

   :Type: :zeek:type:`record`

      free_space_start_filtering: :zeek:type:`int`
         minimum amount of free disk space required to begin document filtering

      free_space_threshold: :zeek:type:`int`
         minimum amount of free disk space required to continue filtering documents and merging word lists

      free_space_stop_filtering: :zeek:type:`int`
         minimum amount of free disk space required to continue content filtering

      delete_quota_threshold: :zeek:type:`count`
         default per-user disk quota

      default_quota_limit: :zeek:type:`count`
         default per-user disk limit

      fs_control_flags: :zeek:type:`count`
         file systems control flags passed as unsigned int

   A series of integers flags used to set quota and content indexing control information for a file system volume in SMB2.
   
   For more information, see MS-SMB2:2.2.39 and MS-FSCC:2.5.2
   

.. zeek:type:: SMB2::FileEA
   :source-code: base/init-bare.zeek 3835 3840

   :Type: :zeek:type:`record`

      ea_name: :zeek:type:`string`
         Specifies the extended attribute name

      ea_value: :zeek:type:`string`
         Contains the extended attribute value

   This information class is used to query or set extended attribute (EA) information for a file.
   
   For more information, see MS-SMB2:2.2.39 and MS-FSCC:2.4.15
   

.. zeek:type:: SMB2::FileEAs
   :source-code: base/init-bare.zeek 3846 3846

   :Type: :zeek:type:`vector` of :zeek:type:`SMB2::FileEA`

   A vector of extended attribute (EA) information for a file.
   
   For more information, see MS-SMB2:2.2.39 and MS-FSCC:2.4.15
   

.. zeek:type:: SMB2::PreAuthIntegrityCapabilities
   :source-code: base/init-bare.zeek 3651 3660

   :Type: :zeek:type:`record`

      hash_alg_count: :zeek:type:`count`
         The number of hash algorithms.

      salt_length: :zeek:type:`count`
         The salt length.

      hash_alg: :zeek:type:`vector` of :zeek:type:`count`
         An array of hash algorithms (counts).

      salt: :zeek:type:`string`
         The salt.

   Preauthentication information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.1
   

.. zeek:type:: SMB2::EncryptionCapabilities
   :source-code: base/init-bare.zeek 3666 3671

   :Type: :zeek:type:`record`

      cipher_count: :zeek:type:`count`
         The number of ciphers.

      ciphers: :zeek:type:`vector` of :zeek:type:`count`
         An array of ciphers.

   Encryption information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.2
   

.. zeek:type:: SMB2::CompressionCapabilities
   :source-code: base/init-bare.zeek 3677 3682

   :Type: :zeek:type:`record`

      alg_count: :zeek:type:`count`
         The number of algorithms.

      algs: :zeek:type:`vector` of :zeek:type:`count`
         An array of compression algorithms.

   Compression information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.3
   

.. zeek:type:: SMB2::NegotiateContextValue
   :source-code: base/init-bare.zeek 3688 3701

   :Type: :zeek:type:`record`

      context_type: :zeek:type:`count`
         Specifies the type of context (preauth or encryption).

      data_length: :zeek:type:`count`
         The length in byte of the data field.

      preauth_info: :zeek:type:`SMB2::PreAuthIntegrityCapabilities` :zeek:attr:`&optional`
         The preauthentication information.

      encryption_info: :zeek:type:`SMB2::EncryptionCapabilities` :zeek:attr:`&optional`
         The encryption information.

      compression_info: :zeek:type:`SMB2::CompressionCapabilities` :zeek:attr:`&optional`
         The compression information.

      netname: :zeek:type:`string` :zeek:attr:`&optional`
         Indicates the server name the client must connect to.

   The context type information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1
   

.. zeek:type:: SMB2::NegotiateContextValues
   :source-code: base/init-bare.zeek 3703 3703

   :Type: :zeek:type:`vector` of :zeek:type:`SMB2::NegotiateContextValue`


Events
++++++

.. zeek:id:: smb1_check_directory_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_check_directory.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, directory_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *check directory*. This is used by the client to verify that
   a specified path resolves to a valid directory on the server.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param directory_name: The directory name to check for existence.
   
   .. zeek:see:: smb1_message smb1_check_directory_response

.. zeek:id:: smb1_check_directory_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_check_directory.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *check directory*. This is the server response to the
   *check directory* request.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. zeek:see:: smb1_message smb1_check_directory_request

.. zeek:id:: smb1_close_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_close.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *close*. This is used by the client to close an instance of an object
   associated with a valid file ID.
   
   For more information, see MS-CIFS:2.2.4.5
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_id: The file identifier being closed.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_create_directory_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_create_directory.bif.zeek 18 18

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, directory_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is used by the client to
   create a new directory on the server, relative to a connected share.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param directory_name: The name of the directory to create.
   
   .. zeek:see:: smb1_message smb1_create_directory_response smb1_transaction2_request

.. zeek:id:: smb1_create_directory_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_create_directory.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is the server response
   to the *create directory* request.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. zeek:see:: smb1_message smb1_create_directory_request smb1_transaction2_request

.. zeek:id:: smb1_echo_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_echo.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, echo_count: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *echo*. This is sent by the client to test the transport layer
   connection with the server.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param echo_count: The number of times the server should echo the data back.
   

   :param data: The data for the server to echo.
   
   .. zeek:see:: smb1_message smb1_echo_response

.. zeek:id:: smb1_echo_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_echo.bif.zeek 36 36

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, seq_num: :zeek:type:`count`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *echo*. This is the server response to the *echo* request.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param seq_num: The sequence number of this echo reply.
   

   :param data: The data echoed back from the client.
   
   .. zeek:see:: smb1_message smb1_echo_request

.. zeek:id:: smb1_logoff_andx
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_logoff_andx.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *logoff andx*. This is used by the client to logoff the user
   connection represented by UID in the SMB Header. The server releases all locks and closes
   all files currently open by this user, disconnects all tree connects, cancels any outstanding
   requests for this UID, and invalidates the UID.
   
   For more information, see MS-CIFS:2.2.4.54
   

   :param c: The connection.
   

   :param is_orig: Indicates which host sent the logoff message.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_negotiate_request
   :source-code: base/protocols/smb/smb1-main.zeek 77 80

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, dialects: :zeek:type:`string_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *negotiate*. This is sent by the client to initiate an SMB
   connection between the client and the server. A *negotiate* exchange MUST be completed
   before any other SMB messages are sent to the server.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param dialects: The SMB dialects supported by the client.
   
   .. zeek:see:: smb1_message smb1_negotiate_response

.. zeek:id:: smb1_negotiate_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_negotiate.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, response: :zeek:type:`SMB1::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *negotiate*. This is the server response to the *negotiate*
   request.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param response: A record structure containing more information from the response.
   
   .. zeek:see:: smb1_message smb1_negotiate_request

.. zeek:id:: smb1_nt_create_andx_request
   :source-code: base/protocols/smb/smb1-main.zeek 137 146

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt create andx*. This is sent by the client to create and open
   a new file, or to open an existing file, or to open and truncate an existing file to zero
   length, or to create a directory, or to create a connection to a named pipe.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param name: The ``name`` attribute  specified in the message.
   
   .. zeek:see:: smb1_message smb1_nt_create_andx_response

.. zeek:id:: smb1_nt_create_andx_response
   :source-code: base/protocols/smb/smb1-main.zeek 148 165

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`, file_size: :zeek:type:`count`, times: :zeek:type:`SMB::MACTimes`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *nt create andx*. This is the server response to the
   *nt create andx* request.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param file_size: Size of the file.
   

   :param times: Timestamps associated with the file in question.
   
   .. zeek:see:: smb1_message smb1_nt_create_andx_request

.. zeek:id:: smb1_nt_cancel_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_nt_cancel.bif.zeek 15 15

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt cancel*. This is sent by the client to request that a currently
   pending request be cancelled.
   
   For more information, see MS-CIFS:2.2.4.65
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_query_information_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_query_information.bif.zeek 18 18

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, filename: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *query information*. This is a deprecated command which
   has been replaced by the *trans2_query_path_information* subcommand. This is used by the
   client to obtain attribute information about a file.
   
   For more information, see MS-CIFS:2.2.4.9
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param filename: The filename that the client is querying.
   
   .. zeek:see:: smb1_message smb1_transaction2_request

.. zeek:id:: smb1_read_andx_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_read_andx.bif.zeek 22 22

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`, offset: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *read andx*. This is sent by the client to read bytes from a regular
   file, a named pipe, or a directly accessible device such as a serial port (COM) or printer
   port (LPT).
   
   For more information, see MS-CIFS:2.2.4.42
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_id: The file identifier being written to.
   

   :param offset: The byte offset the requested read begins at.
   

   :param length: The number of bytes being requested.
   
   .. zeek:see:: smb1_message smb1_read_andx_response

.. zeek:id:: smb1_read_andx_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_read_andx.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, data_len: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *read andx*. This is the server response to the *read andx* request.
   
   For more information, see MS-CIFS:2.2.4.42
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param data_len: The length of data from the requested file.
   
   .. zeek:see:: smb1_message smb1_read_andx_request

.. zeek:id:: smb1_session_setup_andx_request
   :source-code: base/protocols/smb/smb1-main.zeek 252 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, request: :zeek:type:`SMB1::SessionSetupAndXRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *setup andx*. This is sent by the client to configure an SMB session.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param request: The parsed request data of the SMB message. See init-bare for more details.
   
   .. zeek:see:: smb1_message smb1_session_setup_andx_response

.. zeek:id:: smb1_session_setup_andx_response
   :source-code: base/protocols/smb/smb1-main.zeek 257 258

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, response: :zeek:type:`SMB1::SessionSetupAndXResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *setup andx*. This is the server response to the *setup andx* request.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param response: The parsed response data of the SMB message. See init-bare for more details.
   
   .. zeek:see:: smb1_message smb1_session_setup_andx_request

.. zeek:id:: smb1_transaction_request
   :source-code: base/protocols/smb/smb1-main.zeek 262 265

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, name: :zeek:type:`string`, sub_cmd: :zeek:type:`count`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param name: A name string that MAY identify the resource (a specific Mailslot or Named Pipe) 
         against which the operation is performed.
   

   :param sub_cmd: The sub command, some may be parsed and have their own events.
   

   :param parameters: content of the SMB_Data.Trans_Parameters field
   

   :param data: content of the SMB_Data.Trans_Data field
   
   .. zeek:see:: smb1_message smb1_transaction2_request

.. zeek:id:: smb1_transaction_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_transaction.bif.zeek 42 42

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.2
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param parameters: content of the SMB_Data.Trans_Parameters field
   

   :param data: content of the SMB_Data.Trans_Data field

.. zeek:id:: smb1_transaction_secondary_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_transaction_secondary.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Trans_Sec_Args`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction_secondary*. This command
   serves as an additional request data container for the
   Transaction Subprotocol Commands (carried by *transaction* requests).
   
   For more information, see MS-CIFS:2.2.4.34
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param parameters: the SMB_Data.Trans_Parameters field content
   

   :param data: the SMB_Data.Trans_Data field content
   

.. zeek:id:: smb1_transaction2_request
   :source-code: base/protocols/smb/smb1-main.zeek 71 74

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Trans2_Args`, sub_cmd: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2*. This command serves as the transport for the
   Transaction2 Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system. Compared to the
   Transaction Subprotocol Commands, these commands allow clients to set and retrieve Extended
   Attribute key/value pairs, make use of long file names (longer than the original 8.3 format
   names), and perform directory searches, among other tasks.
   
   For more information, see MS-CIFS:2.2.4.46
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param sub_cmd: The sub command, some are parsed and have their own events.
   
   .. zeek:see:: smb1_message smb1_trans2_find_first2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request smb1_transaction_request

.. zeek:id:: smb1_trans2_find_first2_request
   :source-code: base/protocols/smb/smb1-main.zeek 247 250

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Find_First2_Request_Args`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *find first2*. This transaction is used to begin
   a search for file(s) within a directory or for a directory
   
   For more information, see MS-CIFS:2.2.6.2
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param args: A record data structure with arguments given to the command.
   
   .. zeek:see:: smb1_message smb1_transaction2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request

.. zeek:id:: smb1_trans2_query_path_info_request
   :source-code: base/protocols/smb/smb1-main.zeek 242 245

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *query path info*. This transaction is used to
   get information about a specific file or directory.
   
   For more information, see MS-CIFS:2.2.6.6
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_name: File name the request is in reference to. 
   
   .. zeek:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_get_dfs_referral_request

.. zeek:id:: smb1_trans2_get_dfs_referral_request
   :source-code: base/protocols/smb/smb1-main.zeek 237 240

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *get DFS referral*. This transaction is used
   to request a referral for a disk object in DFS.
   
   For more information, see MS-CIFS:2.2.6.16
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_name: File name the request is in reference to.
   
   .. zeek:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_query_path_info_request

.. zeek:id:: smb1_transaction2_secondary_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_transaction2_secondary.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, args: :zeek:type:`SMB1::Trans2_Sec_Args`, parameters: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2 secondary*.
   
   For more information, see MS-CIFS:2.2.4.47.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)`
        version 1 message.
   

   :param args: arguments of the message (SMB_Parameters.Words)
   

   :param parameters: content of the SMB_Data.Trans_Parameters field
   

   :param data: content of the SMB_Data.Trans_Data field

.. zeek:id:: smb1_tree_connect_andx_request
   :source-code: base/protocols/smb/smb1-main.zeek 100 106

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, path: :zeek:type:`string`, service: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree connect andx*. This is sent by the client to establish a
   connection to a server share.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param path: The ``path`` attribute specified in the message.
   

   :param service: The ``service`` attribute specified in the message.
   
   .. zeek:see:: smb1_message smb1_tree_connect_andx_response

.. zeek:id:: smb1_tree_connect_andx_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_tree_connect_andx.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, service: :zeek:type:`string`, native_file_system: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *tree connect andx*. This is the server reply to the *tree connect andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param service: The ``service`` attribute specified in the message.
   

   :param native_file_system: The file system of the remote server as indicate by the server.
   
   .. zeek:see:: smb1_message smb1_tree_connect_andx_request

.. zeek:id:: smb1_tree_disconnect
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_tree_disconnect.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   
   For more information, see MS-CIFS:2.2.4.51
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param is_orig: True if the message was from the originator.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_write_andx_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_write_andx.bif.zeek 20 20

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`, offset: :zeek:type:`count`, data_len: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *write andx*. This is sent by the client to write bytes to a
   regular file, a named pipe, or a directly accessible I/O device such as a serial port (COM)
   or printer port (LPT).
   
   For more information, see MS-CIFS:2.2.4.43
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param offset: The byte offset into the referenced file data is being written.
   

   :param data: The data being written.
   
   .. zeek:see:: smb1_message smb1_write_andx_response

.. zeek:id:: smb1_write_andx_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_write_andx.bif.zeek 36 36

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, written_bytes: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *write andx*. This is the server response to the *write andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.43
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param written_bytes: The number of bytes the server reported having actually written.
   
   .. zeek:see:: smb1_message smb1_write_andx_request

.. zeek:id:: smb1_message
   :source-code: base/bif/plugins/Zeek_SMB.smb1_events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, is_orig: :zeek:type:`bool`)

   Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
   messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Zeek's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb1_empty_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_events.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_error
   :source-code: policy/protocols/smb/log-cmds.zeek 49 64

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)` version 1 messages
   that indicate an error. This event is triggered by an :abbr:`SMB (Server Message Block)` header
   including a status that signals an error.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   

   :param is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb2_close_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_close.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *close*. This is used by the client to close an instance of a
   file that was opened previously with a successful SMB2 CREATE Request.
   
   For more information, see MS-SMB2:2.2.15
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_name: The SMB2 GUID of the file being closed.
   
   .. zeek:see:: smb2_message smb2_close_response

.. zeek:id:: smb2_close_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_close.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::CloseResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *close*. This is sent by the server to indicate that an SMB2 CLOSE
   request was processed successfully.
   
   For more information, see MS-SMB2:2.2.16
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record of attributes returned from the server from the close.
   
   .. zeek:see:: smb2_message smb2_close_request

.. zeek:id:: smb2_create_request
   :source-code: base/protocols/smb/smb2-main.zeek 129 152

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, request: :zeek:type:`SMB2::CreateRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *create*. This is sent by the client to request either creation
   of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param request: A record with more information related to the request.
   
   .. zeek:see:: smb2_message smb2_create_response

.. zeek:id:: smb2_create_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_create.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::CreateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *create*. This is sent by the server to notify the client of
   the status of its SMB2 CREATE request.
   
   For more information, see MS-SMB2:2.2.14
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record with more information related to the response.
   
   .. zeek:see:: smb2_message smb2_create_request

.. zeek:id:: smb2_negotiate_request
   :source-code: base/protocols/smb/smb2-main.zeek 83 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, dialects: :zeek:type:`index_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *negotiate*. This is used by the client to notify the server what
   dialects of the SMB2 Protocol the client understands.
   
   For more information, see MS-SMB2:2.2.3
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param dialects: A vector of the client's supported dialects.
   
   .. zeek:see:: smb2_message smb2_negotiate_response

.. zeek:id:: smb2_negotiate_response
   :source-code: base/protocols/smb/smb2-main.zeek 88 102

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *negotiate*. This is sent by the server to notify the client of
   the preferred common dialect.
   
   For more information, see MS-SMB2:2.2.4
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: The negotiate response data structure.
   
   .. zeek:see:: smb2_message smb2_negotiate_request

.. zeek:id:: smb2_read_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_read.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, offset: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *read*. This is sent by the client to request a read operation on
   the specified file.
   
   For more information, see MS-SMB2:2.2.19
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The GUID being used for the file.
   

   :param offset: How far into the file this read should be taking place.
   

   :param length: The number of bytes of the file being read.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_session_setup_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_session_setup.bif.zeek 18 18

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, request: :zeek:type:`SMB2::SessionSetupRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *session_setup*. This is sent by the client to request a new
   authenticated session within a new or existing SMB 2 Protocol transport connection to the
   server.
   
   For more information, see MS-SMB2:2.2.5
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param request: A record containing more information related to the request.
   
   .. zeek:see:: smb2_message smb2_session_setup_response

.. zeek:id:: smb2_session_setup_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_session_setup.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::SessionSetupResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *session_setup*. This is sent by the server in response to a
   *session_setup* request.
   
   For more information, see MS-SMB2:2.2.6
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record containing more information related to the response.
   
   .. zeek:see:: smb2_message smb2_session_setup_request

.. zeek:id:: smb2_file_rename
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, dst_filename: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *rename* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: A GUID to identify the file.
   

   :param dst_filename: The filename to rename the file into.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_delete
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 38 38

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, delete_pending: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *delete* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param delete_pending: A boolean value to indicate that a file should be deleted 
                   when it's closed if set to T.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_sattr
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 58 58

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, times: :zeek:type:`SMB::MACTimes`, attrs: :zeek:type:`SMB2::FileAttrs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *file* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param times: Timestamps associated with the file in question.
   

   :param attrs: File attributes.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_allocation
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 75 75

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, alloc_size: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *allocation* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param alloc_size: desired allocation size.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_endoffile
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, end_of_file: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *end_of_file* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param end_of_file: the absolute new end of file position as a byte offset from the start of the file
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_mode
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 110 110

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, mode: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *mode* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param mode: specifies how the file will subsequently be accessed.
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_pipe
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 130 130

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, read_mode: :zeek:type:`count`, completion_mode: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *pipe* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param read_mode: specifies if data must be read as a stream of bytes or messages
   

   :param completion_mode: specifies if blocking mode must be enabled or not
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_position
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 148 148

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, current_byte_offset: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *position* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param current_byte_offset: specifies the offset, in bytes, of the file pointer from the beginning of the file
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_shortname
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 165 165

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *short_name* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param file_name: specifies the name of the file to be changed
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_validdatalength
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 182 182

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, valid_data_length: :zeek:type:`int`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *valid_data_length* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param valid_data_length: specifies the new valid data length for the file
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_fullea
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 199 199

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, file_eas: :zeek:type:`SMB2::FileEAs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *full_EA* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param FileEAs: a vector of extended file attributes as defined in MS-FSCC:2.4.15
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_link
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 218 218

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, root_directory: :zeek:type:`count`, file_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *link* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param root_directory: contains the file handle for the directory where the link is to be created
   

   :param file_name: contains the name to be assigned to the newly created link
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_fscontrol
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 235 235

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, fs_control: :zeek:type:`SMB2::Fscontrol`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *fs_control* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param fs_control: contains fs_control info (see MS-FCC 2.5.2)
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link smb2_file_fsobjectid

.. zeek:id:: smb2_file_fsobjectid
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_set_info.bif.zeek 254 254

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, object_id: :zeek:type:`SMB2::GUID`, extended_info: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *fs_object_id* subtype
   
   For more information, see MS-SMB2:2.2.39
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The SMB2 GUID for the file.
   

   :param object_id: contains a 16-bytes GUID that identifies the file system volume (see MS-FCC 2.5.6)
   

   :param extended_info: contains extended information on the file system volume
   
   .. zeek:see:: smb2_message smb2_file_delete smb2_file_sattr smb2_file_allocation smb2_file_endoffile smb2_file_mode smb2_file_pipe smb2_file_position smb2_file_shortname smb2_file_validdatalength smb2_file_fullea smb2_file_link

.. zeek:id:: smb2_tree_connect_request
   :source-code: base/protocols/smb/smb2-main.zeek 104 107

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, path: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree_connect*. This is sent by a client to request access to a
   particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param path: Path of the requested tree.
   
   .. zeek:see:: smb2_message smb2_tree_connect_response

.. zeek:id:: smb2_tree_connect_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_tree_connect.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::TreeConnectResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *tree_connect*. This is sent by the server when a *tree_connect*
   request is successfully processed by the server.
   
   For more information, see MS-SMB2:2.2.10
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record with more information related to the response.
   
   .. zeek:see:: smb2_message smb2_tree_connect_request

.. zeek:id:: smb2_tree_disconnect_request
   :source-code: base/protocols/smb/smb2-main.zeek 119 127

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_tree_disconnect_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_tree_disconnect.bif.zeek 26 26

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the server to logically disconnect
   client access to a server resource.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_write_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_write.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, offset: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the client to write data to the file or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.21
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The GUID being used for the file.
   

   :param offset: How far into the file this write should be taking place.
   

   :param length: The number of bytes of the file being written.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_write_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_write.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the server in response to a write request or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.22
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param length: The number of bytes of the file being written.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_transform_header
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_transform_header.bif.zeek 15 15

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Transform_header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 3.x *transform_header*. This is used by the client or server when sending
   encrypted messages.
   
   For more information, see MS-SMB2:2.2.41
   

   :param c: The connection.
   

   :param hdr: The parsed transformed header message, which is starting with \xfdSMB and different from SMB1 and SMB2 headers.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_message
   :source-code: base/bif/plugins/Zeek_SMB.smb2_events.bif.zeek 20 20

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Zeek's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param is_orig: True if the message came from the originator side.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb2_discarded_messages_state
   :source-code: base/protocols/smb/smb2-main.zeek 350 366

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, state: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 connections for which pending read, ioctl or tree requests exceeds
   the :zeek:see:`SMB::max_pending_messages` setting. This event indicates either
   traffic loss, traffic load-balancing issues, or failures to parse or match
   SMB responses with SMB requests. When this event is raised, internal per-connection
   parser state has been reset.
   

   :param c: The affected connection.
   

   :param state: String describing what kind of state was affected.
          One of read, ioctl or tree.

.. zeek:id:: smb_pipe_connect_heuristic
   :source-code: base/protocols/smb/main.zeek 243 247

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for :abbr:`SMB (Server Message Block)` connections when a
   named pipe has been detected heuristically.  The case when this comes
   up is when the drive mapping isn't seen so the analyzer is not able
   to determine whether to send the data to the files framework or to
   the DCE_RPC analyzer. This heuristic can be tuned by adding or
   removing "named pipe" names from the :zeek:see:`SMB::pipe_filenames`
   const.
   

   :param c: The connection.

.. zeek:id:: smb_discarded_dce_rpc_analyzers
   :source-code: base/protocols/dce-rpc/main.zeek 219 226

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for :abbr:`SMB (Server Message Block)` when the number of
   :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
   analyzers exceeds :zeek:see:`SMB::max_dce_rpc_analyzers`.
   Occurrence of this event may indicate traffic loss, traffic load-balancing
   issues or abnormal SMB protocol usage.
   

   :param c: The connection.
   

.. _plugin-zeek-smtp:

Zeek::SMTP
----------

SMTP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_SMTP`

:zeek:enum:`Analyzer::ANALYZER_SMTP_BDAT`

Options/Constants
+++++++++++++++++

.. zeek:id:: SMTP::bdat_max_line_length
   :source-code: base/init-bare.zeek 370 370

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``4096``

   The maximum line length within a BDAT chunk before a forceful linebreak
   is introduced and a weird is raised. Conventionally, MIME messages
   have a maximum line length of 1000 octets when properly encoded.

Events
++++++

.. zeek:id:: smtp_request
   :source-code: base/protocols/smtp/main.zeek 205 274

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, command: :zeek:type:`string`, arg: :zeek:type:`string`)

   Generated for client-side SMTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the sender of the command is the originator of the TCP
         connection. Note that this is not redundant: the SMTP ``TURN`` command
         allows client and server to flip roles on established SMTP sessions,
         and hence a "request" might still come from the TCP-level responder.
         In practice, however, that will rarely happen as TURN is considered
         insecure and rarely used.
   

   :param command: The request's command, without any arguments.
   

   :param arg: The request command's arguments.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_data smtp_reply
   
   .. note:: Zeek does not support the newer ETRN extension yet.

.. zeek:id:: smtp_reply
   :source-code: base/bif/plugins/Zeek_SMTP.events.bif.zeek 59 59

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, code: :zeek:type:`count`, cmd: :zeek:type:`string`, msg: :zeek:type:`string`, cont_resp: :zeek:type:`bool`)

   Generated for server-side SMTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the sender of the command is the originator of the TCP
         connection. Note that this is not redundant: the SMTP ``TURN`` command
         allows client and server to flip roles on established SMTP sessions,
         and hence a "reply" might still come from the TCP-level originator. In
         practice, however, that will rarely happen as TURN is considered
         insecure and rarely used.
   

   :param code: The reply's numerical code.
   

   :param cmd: TODO.
   

   :param msg: The reply's textual description.
   

   :param cont_resp: True if the reply line is tagged as being continued to the next
         line. If so, further events will be raised and a handler may want to
         reassemble the pieces before processing the response any further.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_data  smtp_request
   
   .. note:: Zeek doesn't support the newer ETRN extension yet.

.. zeek:id:: smtp_data
   :source-code: base/bif/plugins/Zeek_SMTP.events.bif.zeek 85 85

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for DATA transmitted on SMTP sessions. This event is raised for
   subsequent chunks of raw data following the ``DATA`` SMTP command until the
   corresponding end marker ``.`` is seen. A handler may want to reassemble
   the pieces as they come in if stream-analysis is required.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the sender of the data is the originator of the TCP
         connection.
   

   :param data: The raw data. Note that the size of each chunk is undefined and
         depends on specifics of the underlying TCP connection.
   
   .. zeek:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_reply smtp_request skip_smtp_data
   
   .. note:: This event receives the unprocessed raw data. There is a separate
      set of ``mime_*`` events that strip out the outer MIME-layer of emails and
      provide structured access to their content.

.. zeek:id:: smtp_unexpected
   :source-code: base/bif/plugins/Zeek_SMTP.events.bif.zeek 106 106

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`, detail: :zeek:type:`string`)

   Generated for unexpected activity on SMTP sessions. The SMTP analyzer tracks
   the state of SMTP sessions and reports commands and other activity with this
   event that it sees even though it would not expect so at the current point
   of the communication.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the sender of the unexpected activity is the originator of
         the TCP connection.
   

   :param msg: A descriptive message of what was unexpected.
   

   :param detail: The actual SMTP line triggering the event.
   
   .. zeek:see:: smtp_data  smtp_request smtp_reply

.. zeek:id:: smtp_starttls
   :source-code: base/protocols/smtp/main.zeek 407 414

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated if a connection switched to using TLS using STARTTLS or X-ANONYMOUSTLS.
   After this event no more SMTP events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :param c: The connection.
   

Functions
+++++++++

.. zeek:id:: skip_smtp_data
   :source-code: base/bif/plugins/Zeek_SMTP.functions.bif.zeek 12 12

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`any`

   Skips SMTP data until the next email in a connection.
   

   :param c: The SMTP connection.
   
   .. zeek:see:: skip_http_entity_data

.. _plugin-zeek-snmp:

Zeek::SNMP
----------

SNMP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_SNMP`

Types
+++++

.. zeek:type:: SNMP::Header
   :source-code: base/init-bare.zeek 4859 4864

   :Type: :zeek:type:`record`

      version: :zeek:type:`count`

      v1: :zeek:type:`SNMP::HeaderV1` :zeek:attr:`&optional`
         Set when ``version`` is 0.

      v2: :zeek:type:`SNMP::HeaderV2` :zeek:attr:`&optional`
         Set when ``version`` is 1.

      v3: :zeek:type:`SNMP::HeaderV3` :zeek:attr:`&optional`
         Set when ``version`` is 3.

   A generic SNMP header data structure that may include data from
   any version of SNMP.  The value of the ``version`` field
   determines what header field is initialized.

.. zeek:type:: SNMP::HeaderV1
   :source-code: base/init-bare.zeek 4824 4826

   :Type: :zeek:type:`record`

      community: :zeek:type:`string`

   The top-level message data structure of an SNMPv1 datagram, not
   including the PDU data.  See :rfc:`1157`.

.. zeek:type:: SNMP::HeaderV2
   :source-code: base/init-bare.zeek 4830 4832

   :Type: :zeek:type:`record`

      community: :zeek:type:`string`

   The top-level message data structure of an SNMPv2 datagram, not
   including the PDU data.  See :rfc:`1901`.

.. zeek:type:: SNMP::HeaderV3
   :source-code: base/init-bare.zeek 4844 4854

   :Type: :zeek:type:`record`

      id: :zeek:type:`count`

      max_size: :zeek:type:`count`

      flags: :zeek:type:`count`

      auth_flag: :zeek:type:`bool`

      priv_flag: :zeek:type:`bool`

      reportable_flag: :zeek:type:`bool`

      security_model: :zeek:type:`count`

      security_params: :zeek:type:`string`

      pdu_context: :zeek:type:`SNMP::ScopedPDU_Context` :zeek:attr:`&optional`

   The top-level message data structure of an SNMPv3 datagram, not
   including the PDU data.  See :rfc:`3412`.

.. zeek:type:: SNMP::PDU
   :source-code: base/init-bare.zeek 4914 4919

   :Type: :zeek:type:`record`

      request_id: :zeek:type:`int`

      error_status: :zeek:type:`int`

      error_index: :zeek:type:`int`

      bindings: :zeek:type:`SNMP::Bindings`

   A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.

.. zeek:type:: SNMP::TrapPDU
   :source-code: base/init-bare.zeek 4922 4929

   :Type: :zeek:type:`record`

      enterprise: :zeek:type:`string`

      agent: :zeek:type:`addr`

      generic_trap: :zeek:type:`int`

      specific_trap: :zeek:type:`int`

      time_stamp: :zeek:type:`count`

      bindings: :zeek:type:`SNMP::Bindings`

   A ``Trap-PDU`` data structure from :rfc:`1157`.

.. zeek:type:: SNMP::BulkPDU
   :source-code: base/init-bare.zeek 4932 4937

   :Type: :zeek:type:`record`

      request_id: :zeek:type:`int`

      non_repeaters: :zeek:type:`count`

      max_repetitions: :zeek:type:`count`

      bindings: :zeek:type:`SNMP::Bindings`

   A ``BulkPDU`` data structure from :rfc:`3416`.

.. zeek:type:: SNMP::ScopedPDU_Context
   :source-code: base/init-bare.zeek 4837 4840

   :Type: :zeek:type:`record`

      engine_id: :zeek:type:`string`

      name: :zeek:type:`string`

   The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
   including the PDU data (i.e. just the "context" fields).
   See :rfc:`3412`.

.. zeek:type:: SNMP::ObjectValue
   :source-code: base/init-bare.zeek 4875 4882

   :Type: :zeek:type:`record`

      tag: :zeek:type:`count`

      oid: :zeek:type:`string` :zeek:attr:`&optional`

      signed: :zeek:type:`int` :zeek:attr:`&optional`

      unsigned: :zeek:type:`count` :zeek:attr:`&optional`

      address: :zeek:type:`addr` :zeek:attr:`&optional`

      octets: :zeek:type:`string` :zeek:attr:`&optional`

   A generic SNMP object value, that may include any of the
   valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
   The value is decoded whenever possible and assigned to
   the appropriate field, which can be determined from the value
   of the ``tag`` field.  For tags that can't be mapped to an
   appropriate type, the ``octets`` field holds the BER encoded
   ASN.1 content if there is any (though, ``octets`` is may also
   be used for other tags such as OCTET STRINGS or Opaque).  Null
   values will only have their corresponding tag value set.

.. zeek:type:: SNMP::Binding
   :source-code: base/init-bare.zeek 4904 4907

   :Type: :zeek:type:`record`

      oid: :zeek:type:`string`

      value: :zeek:type:`SNMP::ObjectValue`

   The ``VarBind`` data structure from either :rfc:`1157` or
   :rfc:`3416`, which maps an Object Identifier to a value.

.. zeek:type:: SNMP::Bindings
   :source-code: base/init-bare.zeek 4911 4911

   :Type: :zeek:type:`vector` of :zeek:type:`SNMP::Binding`

   A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
   A sequences of :zeek:see:`SNMP::Binding`, which maps an OIDs to values.

Events
++++++

.. zeek:id:: snmp_get_request
   :source-code: base/protocols/snmp/main.zeek 109 113

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_get_next_request
   :source-code: base/protocols/snmp/main.zeek 121 125

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
   :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_response
   :source-code: base/protocols/snmp/main.zeek 127 144

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
   ``Response-PDU`` from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_set_request
   :source-code: base/protocols/snmp/main.zeek 146 150

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_trap
   :source-code: base/protocols/snmp/main.zeek 152 155

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::TrapPDU`)

   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_get_bulk_request
   :source-code: base/protocols/snmp/main.zeek 115 119

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::BulkPDU`)

   An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_inform_request
   :source-code: base/protocols/snmp/main.zeek 157 160

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_trapV2
   :source-code: base/protocols/snmp/main.zeek 162 165

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_report
   :source-code: base/protocols/snmp/main.zeek 167 170

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, pdu: :zeek:type:`SNMP::PDU`)

   An SNMP ``Report-PDU`` message from :rfc:`3416`.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param pdu: An SNMP PDU data structure.

.. zeek:id:: snmp_unknown_pdu
   :source-code: base/protocols/snmp/main.zeek 172 175

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, tag: :zeek:type:`count`)

   An SNMP PDU message of unknown type.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param tag: The tag of the unknown SNMP PDU.

.. zeek:id:: snmp_unknown_scoped_pdu
   :source-code: base/protocols/snmp/main.zeek 177 180

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`, tag: :zeek:type:`count`)

   An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
   an encrypted PDU was in the datagram).
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :param tag: The tag of the unknown SNMP PDU scope.

.. zeek:id:: snmp_encrypted_pdu
   :source-code: base/protocols/snmp/main.zeek 182 185

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, header: :zeek:type:`SNMP::Header`)

   An SNMPv3 encrypted PDU message.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.

.. zeek:id:: snmp_unknown_header_version
   :source-code: base/bif/plugins/Zeek_SNMP.events.bif.zeek 168 168

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, version: :zeek:type:`count`)

   A datagram with an unknown SNMP version.
   

   :param c: The connection over which the SNMP datagram is sent.
   

   :param is_orig: The endpoint which sent the SNMP datagram.
   

   :param version: The value of the unknown SNMP version.

.. _plugin-zeek-socks:

Zeek::SOCKS
-----------

SOCKS analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_SOCKS`

Events
++++++

.. zeek:id:: socks_request
   :source-code: base/protocols/socks/main.zeek 76 89

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, request_type: :zeek:type:`count`, sa: :zeek:type:`SOCKS::Address`, p: :zeek:type:`port`, user: :zeek:type:`string`)

   Generated when a SOCKS request is analyzed.
   

   :param c: The parent connection of the proxy.
   

   :param version: The version of SOCKS this message used.
   

   :param request_type: The type of the request.
   

   :param sa: Address that the tunneled traffic should be sent to.
   

   :param p: The destination port for the proxied traffic.
   

   :param user: Username given for the SOCKS connection.  This is not yet implemented
         for SOCKSv5.

.. zeek:id:: socks_reply
   :source-code: base/protocols/socks/main.zeek 91 102

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, reply: :zeek:type:`count`, sa: :zeek:type:`SOCKS::Address`, p: :zeek:type:`port`)

   Generated when a SOCKS reply is analyzed.
   

   :param c: The parent connection of the proxy.
   

   :param version: The version of SOCKS this message used.
   

   :param reply: The status reply from the server.
   

   :param sa: The address that the server sent the traffic to.
   

   :param p: The destination port for the proxied traffic.

.. zeek:id:: socks_login_userpass_request
   :source-code: base/protocols/socks/main.zeek 104 113

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated when a SOCKS client performs username and password based login.
   

   :param c: The parent connection of the proxy.
   

   :param user: The given username.
   

   :param password: The given password.

.. zeek:id:: socks_login_userpass_reply
   :source-code: base/protocols/socks/main.zeek 115 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`)

   Generated when a SOCKS server replies to a username/password login attempt.
   

   :param c: The parent connection of the proxy.
   

   :param code: The response code for the attempted login.

.. _plugin-zeek-spicy:

Zeek::Spicy
-----------

Support for Spicy parsers (.hlto)

.. _plugin-zeek-ssh:

Zeek::SSH
---------

Secure Shell analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_SSH`

Types
+++++

.. zeek:type:: SSH::Algorithm_Prefs
   :source-code: base/init-bare.zeek 2950 2955

   :Type: :zeek:type:`record`

      client_to_server: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         The algorithm preferences for client to server communication

      server_to_client: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         The algorithm preferences for server to client communication

   The client and server each have some preferences for the algorithms used
   in each direction.

.. zeek:type:: SSH::Capabilities
   :source-code: base/init-bare.zeek 2962 2977

   :Type: :zeek:type:`record`

      kex_algorithms: :zeek:type:`string_vec`
         Key exchange algorithms

      server_host_key_algorithms: :zeek:type:`string_vec`
         The algorithms supported for the server host key

      encryption_algorithms: :zeek:type:`SSH::Algorithm_Prefs`
         Symmetric encryption algorithm preferences

      mac_algorithms: :zeek:type:`SSH::Algorithm_Prefs`
         Symmetric MAC algorithm preferences

      compression_algorithms: :zeek:type:`SSH::Algorithm_Prefs`
         Compression algorithm preferences

      languages: :zeek:type:`SSH::Algorithm_Prefs` :zeek:attr:`&optional`
         Language preferences

      is_server: :zeek:type:`bool`
         Are these the capabilities of the server?

   This record lists the preferences of an SSH endpoint for
   algorithm selection. During the initial :abbr:`SSH (Secure Shell)`
   key exchange, each endpoint lists the algorithms
   that it supports, in order of preference. See
   :rfc:`4253#section-7.1` for details.

Events
++++++

.. zeek:id:: ssh_server_version
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`string`)

   An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
   from the server. This contains an identification string that's used
   for version identification. See :rfc:`4253#section-4.2` for
   details.
   

   :param c: The connection over which the message was sent.
   

   :param version: The identification string
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh_client_version
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 37 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`string`)

   An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
   from the client. This contains an identification string that's used
   for version identification. See :rfc:`4253#section-4.2` for
   details.
   

   :param c: The connection over which the message was sent.
   

   :param version: The identification string
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh_auth_successful
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 60 60

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, auth_method_none: :zeek:type:`bool`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had a successful
   authentication. This determination is based on packet size
   analysis, and errs on the side of caution - that is, if there's any
   doubt about the authentication success, this event is *not* raised.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param auth_method_none: This is true if the analyzer detected a
      successful connection before any authentication challenge. The
      :abbr:`SSH (Secure Shell)` protocol provides a mechanism for
      unauthenticated access, which some servers support.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh_auth_attempted
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, authenticated: :zeek:type:`bool`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had an authentication attempt.
   This determination is based on packet size analysis, and errs
   on the side of caution - that is, if there's any doubt about
   whether or not an authentication attempt occurred, this event is
   *not* raised.
   
   At this point in the protocol, all we can determine is whether
   or not the user is authenticated. We don't know if the particular
   attempt succeeded or failed, since some servers require multiple
   authentications (e.g. require both a password AND a pubkey), and
   could return an authentication failed message which is marked
   as a partial success.
   
   This event will often be raised multiple times per connection.
   In almost all connections, it will be raised once unless
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param authenticated: This is true if the analyzer detected a
      successful connection from the authentication attempt.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh_capabilities
   :source-code: base/protocols/ssh/main.zeek 287 310

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, cookie: :zeek:type:`string`, capabilities: :zeek:type:`SSH::Capabilities`)

   During the initial :abbr:`SSH (Secure Shell)` key exchange, each
   endpoint lists the algorithms that it supports, in order of
   preference. This event is generated for each endpoint, when the
   SSH_MSG_KEXINIT message is seen. See :rfc:`4253#section-7.1` for
   details.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param cookie: The SSH_MSG_KEXINIT cookie - a random value generated by
      the sender.
   

   :param capabilities: The list of algorithms and languages that the sender
      advertises support for, in order of preference.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_server_host_key
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 135 135

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, key: :zeek:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH2.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param key: The server's public host key. Note that this is the public key
      itself, and not just the fingerprint or hash.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init ssh2_gss_init
      ssh2_rsa_secret

.. zeek:id:: ssh1_server_host_key
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 163 163

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, modulus: :zeek:type:`string`, exponent: :zeek:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH1.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param p: The exponent for the server's public host key (note this parameter
      is truly the exponent even though named *p* and the *exponent* parameter
      will eventually replace it).
   

   :param e: The prime modulus for the server's public host key (note this parameter
      is truly the modulus even though named *e* and the *modulus* parameter
      will eventually replace it).
   

   :param modulus: The prime modulus of the server's public host key.
   

   :param exponent: The exponent of the server's public host key.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh_server_host_key
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 193 193

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hash: :zeek:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH1 or SSH2 and provides
   a fingerprint of the server's host key.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param hash: an MD5 hash fingerprint associated with the server's host key.
         For SSH2, this is the hash of the "server public host key" string as
         seen on the wire in the Diffie-Hellman key exchange reply message
         (the string itself, excluding the 4-byte length associated with it),
         which is also the *key* parameter of :zeek:see:`ssh2_server_host_key`
         For SSH1, this is the hash of the combined multiprecision integer
         strings representing the RSA1 key's prime modulus and public exponent
         (concatenated in that order) as seen on the wire,
         which are also the parameters of :zeek:see:`ssh1_server_host_key`.
         In either case, the hash is the same "fingerprint" string as presented
         by other traditional tools, ``ssh``, ``ssh-keygen``, etc, and is the
         hexadecimal representation of all 16 MD5 hash bytes delimited by colons.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh_encrypted_packet
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 217 217

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, orig: :zeek:type:`bool`, len: :zeek:type:`count`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   encrypted packet is seen. This event is not handled by default, but
   is provided for heuristic analysis scripts. Note that you have to set
   :zeek:id:`SSH::disable_analyzer_after_detection` to false to use this
   event. This carries a performance penalty.
   

   :param c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :param orig: Whether the packet was sent by the originator of the TCP
      connection.
   

   :param len: The length of the :abbr:`SSH (Secure Shell)` payload, in
      bytes. Note that this ignores reassembly, as this is unknown.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_dh_server_params
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 237 237

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, p: :zeek:type:`string`, q: :zeek:type:`string`)

   Generated if the connection uses a Diffie-Hellman Group Exchange
   key exchange method. This event contains the server DH parameters,
   which are sent in the SSH_MSG_KEY_DH_GEX_GROUP message as defined in
   :rfc:`4419#section-3`.
   

   :param c: The connection.
   

   :param p: The DH prime modulus.
   

   :param q: The DH generator.
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_gss_error
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 259 259

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, major_status: :zeek:type:`count`, minor_status: :zeek:type:`count`, err_msg: :zeek:type:`string`)

   In the event of a GSS-API error on the server, the server MAY send
   send an error message with some additional details. This event is
   generated when such an error message is seen. For more information,
   see :rfc:`4462#section-2.1`.
   

   :param c: The connection.
   

   :param major_status: GSS-API major status code.
   

   :param minor_status: GSS-API minor status code.
   

   :param err_msg: Detailed human-readable error message
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_ecc_key
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 281 281

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, q: :zeek:type:`string`)

   The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
   :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
   algorithms use two ephemeral key pairs to generate a shared
   secret. This event is generated when either the client's or
   server's ephemeral public key is seen. For more information, see:
   :rfc:`5656#section-4`.
   

   :param c: The connection.
   

   :param is_orig: Did this message come from the originator?
   

   :param q: The ephemeral public key
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_ecc_init
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 303 303

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
   :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
   algorithms use two ephemeral key pairs to generate a shared
   secret. This event is generated when either the SSH_MSG_KEX_ECDH_INIT
   or SSH_MSG_ECMQV_INIT message is observed. By definition, these need
   to originate from the client and not from the server.
   For more information, see:
   :rfc:`5656#section-4`.
   

   :param c: The connection.
   

   :param is_orig: Did this message come from the originator?
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_dh_gex_init
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 321 321

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated if the connection uses a Diffie-Hellman Group Exchange
   key exchange method. This event contains the direction of the key
   exchange setup, which is indicated by the the SSH_MSG_KEX_DH_GEX_INIT
   message as defined in :rfc:`4419#section-3`.
   

   :param c: The connection.
   

   :param is_orig: Did this message come from the originator?
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_gss_init
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 338 338

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   In the event of a GSS-API key exchange, this event is raised on
   SSH_MSG_KEXGSS_INIT message.
   For more information see :rfc:`4462#section-2.1`.
   

   :param c: The connection.
   

   :param is_orig: Did this message come from the originator?
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. zeek:id:: ssh2_rsa_secret
   :source-code: base/bif/plugins/Zeek_SSH.events.bif.zeek 356 356

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   In the event of a GSS-API key exchange, this event is raised on
   SSH_MSG_KEXRSA_PUBKEY message. This message is sent first by the server,
   after which the server will respond with a SSH_MSG_KEXRSA_SECRET message.
   For more information see :rfc:`4432#section-4`.
   

   :param c: The connection.
   

   :param is_orig: Did this message come from the originator?
   
   .. zeek:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_successful ssh_auth_attempted
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key ssh2_ecc_init ssh2_dh_gex_init
      ssh2_gss_init ssh2_rsa_secret

.. _plugin-zeek-ssl:

Zeek::SSL
---------

SSL/TLS and DTLS analyzers

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_DTLS`

:zeek:enum:`Analyzer::ANALYZER_SSL`

Options/Constants
+++++++++++++++++

.. zeek:id:: SSL::dtls_max_version_errors
   :source-code: base/init-bare.zeek 4604 4604

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   Number of non-DTLS frames that can occur in a DTLS connection before
   parsing of the connection is suspended.
   DTLS does not immediately stop parsing a connection because other protocols
   might be interleaved in the same UDP "connection".

.. zeek:id:: SSL::dtls_max_reported_version_errors
   :source-code: base/init-bare.zeek 4607 4607

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1``

   Maximum number of invalid version errors to report in one DTLS connection.

.. zeek:id:: SSL::max_alerts_per_record
   :source-code: base/init-bare.zeek 4612 4612

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10``

   Maximum number of Alert messages parsed from an SSL record with
   content_type alert (21). The remaining alerts are discarded. For
   TLS 1.3 connections, this is implicitly 1 as defined by RFC 8446.

Types
+++++

.. zeek:type:: SSL::SignatureAndHashAlgorithm
   :source-code: base/init-bare.zeek 4590 4593

   :Type: :zeek:type:`record`

      HashAlgorithm: :zeek:type:`count`
         Hash algorithm number

      SignatureAlgorithm: :zeek:type:`count`
         Signature algorithm number


.. zeek:type:: SSL::PSKIdentity
   :source-code: base/init-bare.zeek 4595 4598

   :Type: :zeek:type:`record`

      identity: :zeek:type:`string`
         PSK identity

      obfuscated_ticket_age: :zeek:type:`count`


Events
++++++

.. zeek:id:: ssl_client_hello
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 41 41

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, record_version: :zeek:type:`count`, possible_ts: :zeek:type:`time`, client_random: :zeek:type:`string`, session_id: :zeek:type:`string`, ciphers: :zeek:type:`index_vec`, comp_methods: :zeek:type:`index_vec`)

   Generated for an SSL/TLS client's initial *hello* message.  SSL/TLS sessions
   start with an unencrypted handshake, and Zeek extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :param c: The connection.
   

   :param version: The protocol version as extracted from the client's message.  The
            values are standardized as part of the SSL/TLS protocol. The
            :zeek:id:`SSL::version_strings` table maps them to descriptive names.
   

   :param record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :param possible_ts: The current time as sent by the client. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care.
   

   :param session_id: The session ID sent by the client (if any).
   

   :param client_random: The random value sent by the client. For version 2 connections,
   		  the client challenge is returned.
   

   :param ciphers: The list of ciphers the client offered to use. The values are
            standardized as part of the SSL/TLS protocol. The
            :zeek:id:`SSL::cipher_desc` table maps them to descriptive names.
   

   :param comp_methods: The list of compression methods that the client offered to use.
                 This value is not sent in TLSv1.3 or SSLv2.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_handshake_message
      ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_connection_flipped

.. zeek:id:: ssl_server_hello
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 86 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, version: :zeek:type:`count`, record_version: :zeek:type:`count`, possible_ts: :zeek:type:`time`, server_random: :zeek:type:`string`, session_id: :zeek:type:`string`, cipher: :zeek:type:`count`, comp_method: :zeek:type:`count`)

   Generated for an SSL/TLS server's initial *hello* message. SSL/TLS sessions
   start with an unencrypted handshake, and Zeek extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :param c: The connection.
   

   :param version: The protocol version as extracted from the server's message.
            The values are standardized as part of the SSL/TLS protocol. The
            :zeek:id:`SSL::version_strings` table maps them to descriptive names.
   

   :param record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :param possible_ts: The current time as sent by the server. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care. This value
                is meaningless in SSLv2 and TLSv1.3.
   

   :param session_id: The session ID as sent back by the server (if any). This value is not
               sent in TLSv1.3.
   

   :param server_random: The random value sent by the server. For version 2 connections,
   		  the connection-id is returned. Note - the full 32 bytes are included in
   		  server_random. This means that the 4 bytes present in possible_ts are repeated;
   		  if you do not want this behavior ignore the first 4 bytes.
   

   :param cipher: The cipher chosen by the server.  The values are standardized as part
           of the SSL/TLS protocol. The :zeek:id:`SSL::cipher_desc` table maps
           them to descriptive names.
   

   :param comp_method: The compression method chosen by the client. The values are
                standardized as part of the SSL/TLS protocol. This value is not
                sent in TLSv1.3 or SSLv2.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_extension
      ssl_session_ticket_handshake x509_certificate
      ssl_dh_server_params ssl_handshake_message ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_connection_flipped

.. zeek:id:: ssl_extension
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 115 115

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, code: :zeek:type:`count`, val: :zeek:type:`string`)

   Generated for SSL/TLS extensions seen in an initial handshake.  SSL/TLS
   sessions start with an unencrypted handshake, and Zeek extracts as much
   information out of that as it can. This event provides access to any
   extensions either side sends as part of an extended *hello* message.
   
   Note that Zeek offers more specialized events for a few extensions.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param code: The numerical code of the extension.  The values are standardized as
         part of the SSL/TLS protocol. The :zeek:id:`SSL::extensions` table maps
         them to descriptive names.
   

   :param val: The raw extension value that was sent in the message.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension_ec_point_formats
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_connection_flipped ssl_extension_connection_id

.. zeek:id:: ssl_extension_elliptic_curves
   :source-code: policy/protocols/ssl/ssl-log-ext.zeek 103 111

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, curves: :zeek:type:`index_vec`)

   Generated for an SSL/TLS Elliptic Curves extension. This TLS extension is
   defined in :rfc:`4492` and sent by the client in the initial handshake. It
   gives the list of elliptic curves supported by the client.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param curves: List of supported elliptic curves.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_ec_point_formats ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm
      ssl_extension_key_share ssl_rsa_client_pms ssl_server_signature
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_ec_point_formats
   :source-code: policy/protocols/ssl/ssl-log-ext.zeek 93 101

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, point_formats: :zeek:type:`index_vec`)

   Generated for an SSL/TLS Supported Point Formats extension. This TLS extension
   is defined in :rfc:`4492` and sent by the client and/or server in the initial
   handshake. It gives the list of elliptic curve point formats supported by the
   client.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param point_formats: List of supported point formats.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_signature_algorithm
   :source-code: policy/protocols/ssl/ssl-log-ext.zeek 159 178

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, signature_algorithms: :zeek:type:`signature_and_hashalgorithm_vec`)

   Generated for an Signature Algorithms extension. This TLS extension
   is defined in :rfc:`5246` and sent by the client in the initial
   handshake. It gives the list of signature and hash algorithms supported by the
   client.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param signature_algorithms: List of supported signature and hash algorithm pairs.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_key_share
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 214 214

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, curves: :zeek:type:`index_vec`)

   Generated for a Key Share extension. This TLS extension is defined in TLS1.3-draft16
   and sent by the client and the server in the initial handshake. It gives the list of
   named groups supported by the client and chosen by the server.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param curves: List of supported/chosen named groups.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_pre_shared_key_client_hello
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 240 240

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, identities: :zeek:type:`psk_identity_vec`, binders: :zeek:type:`string_vec`)

   Generated for the pre-shared key extension as it is sent in the TLS 1.3 client hello.
   
   The extension lists the identities the client is willing to negotiate with the server;
   they can either be pre-shared or be based on previous handshakes.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param identities: A list of the identities the client is willing to negotiate with the server.
   

   :param binders: A series of HMAC values; for computation, see the TLS 1.3 RFC.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature ssl_extension_pre_shared_key_server_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_pre_shared_key_server_hello
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 262 262

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, selected_identity: :zeek:type:`count`)

   Generated for the pre-shared key extension as it is sent in the TLS 1.3 server hello.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param selected_identity: The identity the server chose as a 0-based index into the identities
                      the client sent.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_ecdh_server_params
   :source-code: base/protocols/ssl/main.zeek 318 323

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, curve: :zeek:type:`count`, point: :zeek:type:`string`)

   Generated if a server uses an ECDH-anon or ECDHE cipher suite using a named curve
   This event contains the named curve name and the server ECDH parameters contained
   in the ServerKeyExchange message as defined in :rfc:`4492`.
   

   :param c: The connection.
   

   :param curve: The curve parameters.
   

   :param point: The server's ECDH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_client_params ssl_rsa_client_pms

.. zeek:id:: ssl_dh_server_params
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 297 297

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, p: :zeek:type:`string`, q: :zeek:type:`string`, Ys: :zeek:type:`string`)

   Generated if a server uses a DH-anon or DHE cipher suite. This event contains
   the server DH parameters, contained in the ServerKeyExchange message as
   defined in :rfc:`5246`.
   

   :param c: The connection.
   

   :param p: The DH prime modulus.
   

   :param q: The DH generator.
   

   :param Ys: The server's DH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. zeek:id:: ssl_server_signature
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 320 320

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, signature_and_hashalgorithm: :zeek:type:`SSL::SignatureAndHashAlgorithm`, signature: :zeek:type:`string`)

   Generated if a server uses a non-anonymous DHE or ECDHE cipher suite. This event
   contains the server signature over the key exchange parameters contained in
   the ServerKeyExchange message as defined in :rfc:`4492` and :rfc:`5246`.
   

   :param c: The connection.
   

   :param signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct. This field is only present
                                starting with TLSv1.2 and DTLSv1.2. Earlier versions
                                used a hardcoded hash algorithm. For protocol versions
                                below D(TLS)v1.2 this field is filled with an dummy
                                value of 256.
   

   :param signature: Signature part of the digitally_signed struct. The private key
              corresponding to the certified public key in the server's certificate
              message is used for signing.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_rsa_client_pms
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. zeek:id:: ssl_ecdh_client_params
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 334 334

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, point: :zeek:type:`string`)

   Generated if a client uses an ECDH-anon or ECDHE cipher suite. This event
   contains the client ECDH public value contained in the ClientKeyExchange
   message as defined in :rfc:`4492`.
   

   :param c: The connection.
   

   :param point: The client's ECDH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_rsa_client_pms

.. zeek:id:: ssl_dh_client_params
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 348 348

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, Yc: :zeek:type:`string`)

   Generated if a client uses a DH-anon or DHE cipher suite. This event contains
   the client DH parameters contained in the ClientKeyExchange message as
   defined in :rfc:`5246`.
   

   :param c: The connection.
   

   :param Yc: The client's DH public key.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_ecdh_server_params ssl_ecdh_client_params ssl_rsa_client_pms

.. zeek:id:: ssl_rsa_client_pms
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 362 362

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, pms: :zeek:type:`string`)

   Generated if a client uses RSA key exchange. This event contains the client
   encrypted pre-master secret which is encrypted using the public key of the
   server's certificate as defined in :rfc:`5246`.
   

   :param c: The connection.
   

   :param pms: The encrypted pre-master secret.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. zeek:id:: ssl_extension_application_layer_protocol_negotiation
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 388 388

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, protocols: :zeek:type:`string_vec`)

   Generated for an SSL/TLS Application-Layer Protocol Negotiation extension.
   This TLS extension is defined in draft-ietf-tls-applayerprotoneg and sent in
   the initial handshake. It contains the list of client supported application
   protocols by the client or the server, respectively.
   
   At the moment it is mostly used to negotiate the use of SPDY / HTTP2.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param protocols: List of supported application layer protocols.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_server_name
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 414 414

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, names: :zeek:type:`string_vec`)

   Generated for an SSL/TLS Server Name extension. This SSL/TLS extension is
   defined in :rfc:`3546` and sent by the client in the initial handshake. It
   contains the name of the server it is contacting. This information can be
   used by the server to choose the correct certificate for the host the client
   wants to contact.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param names: A list of server names (DNS hostnames).
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_signed_certificate_timestamp
   :source-code: policy/protocols/ssl/validate-sct.zeek 77 80

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, version: :zeek:type:`count`, logid: :zeek:type:`string`, timestamp: :zeek:type:`count`, signature_and_hashalgorithm: :zeek:type:`SSL::SignatureAndHashAlgorithm`, signature: :zeek:type:`string`)

   Generated for the signed_certificate_timestamp TLS extension as defined in
   :rfc:`6962`. The extension is used to transmit signed proofs that are
   used for Certificate Transparency.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param version: the version of the protocol to which the SCT conforms. Always
            should be 0 (representing version 1)
   

   :param logid: 32 bit key id
   

   :param timestamp: the NTP Time when the entry was logged measured since
              the epoch, ignoring leap seconds, in milliseconds.
   

   :param signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct
   

   :param signature: signature part of the digitally_signed struct
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_application_layer_protocol_negotiation
      x509_ocsp_ext_signed_certificate_timestamp sct_verify
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_supported_versions
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 473 473

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, versions: :zeek:type:`index_vec`)

   Generated for an TLS Supported Versions extension. This TLS extension
   is defined in the TLS 1.3 rfc and sent by the client in the initial handshake.
   It contains the TLS versions that it supports. This information can be used by
   the server to choose the best TLS version o use.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param versions: List of supported TLS versions.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_psk_key_exchange_modes
   :source-code: policy/protocols/ssl/ssl-log-ext.zeek 139 147

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, modes: :zeek:type:`index_vec`)

   Generated for an TLS Pre-Shared Key Exchange Modes extension. This TLS extension is defined
   in the TLS 1.3 rfc and sent by the client in the initial handshake. It contains the
   list of Pre-Shared Key Exchange Modes that it supports.

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param versions: List of supported Pre-Shared Key Exchange Modes.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_supported_versions ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello
      ssl_extension_connection_id

.. zeek:id:: ssl_extension_connection_id
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 517 517

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, cid: :zeek:type:`string`)

   Generated for an DTLS Connection ID extension. This TLS extension is defined
   in the RFC 9146 and sent by the client or the server to signify that Connection IDs should
   be used for the connection.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param cid: The connection ID given by the client or the server.
   
   .. zeek:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_supported_versions ssl_extension_signed_certificate_timestamp
      ssl_extension_pre_shared_key_server_hello ssl_extension_pre_shared_key_client_hello

.. zeek:id:: ssl_established
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 533 533

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated at the end of an SSL/TLS handshake. SSL/TLS sessions start with
   an unencrypted handshake, and Zeek extracts as much information out of that
   as it can. This event signals the time when an SSL/TLS has finished the
   handshake and its endpoints consider it as fully established. Typically,
   everything from now on will be encrypted.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :param c: The connection.
   
   .. zeek:see:: ssl_alert ssl_client_hello  ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate

.. zeek:id:: ssl_alert
   :source-code: base/protocols/ssl/main.zeek 475 481

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, level: :zeek:type:`count`, desc: :zeek:type:`count`)

   Generated for SSL/TLS alert records. SSL/TLS sessions start with an
   unencrypted handshake, and Zeek extracts as much information out of that as
   it can. If during that handshake, an endpoint encounters a fatal error, it
   sends an *alert* record, that in turn triggers this event. After an *alert*,
   any endpoint may close the connection immediately.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param level: The severity level, as sent in the *alert*. The values are defined as
          part of the SSL/TLS protocol.
   

   :param desc: A numerical value identifying the cause of the *alert*. The values are
         defined as part of the SSL/TLS protocol.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake

.. zeek:id:: ssl_session_ticket_handshake
   :source-code: policy/protocols/ssl/ssl-log-ext.zeek 68 73

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ticket_lifetime_hint: :zeek:type:`count`, ticket: :zeek:type:`string`)

   Generated for SSL/TLS handshake messages that are a part of the
   stateless-server session resumption mechanism. SSL/TLS sessions start with
   an unencrypted handshake, and Zeek extracts as much information out of that
   as it can. This event is raised when an SSL/TLS server passes a session
   ticket to the client that can later be used for resuming the session. The
   mechanism is described in :rfc:`4507`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :param c: The connection.
   

   :param ticket_lifetime_hint: A hint from the server about how long the ticket
                         should be stored by the client.
   

   :param ticket: The raw ticket data.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert

.. zeek:id:: ssl_heartbeat
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 606 606

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, length: :zeek:type:`count`, heartbeat_type: :zeek:type:`count`, payload_length: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for SSL/TLS heartbeat messages that are sent before session
   encryption starts. Generally heartbeat messages should rarely be seen in
   normal TLS traffic. Heartbeats are described in :rfc:`6520`.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param length: length of the entire heartbeat message.
   

   :param heartbeat_type: type of the heartbeat message. Per RFC, 1 = request, 2 = response.
   

   :param payload_length: length of the payload of the heartbeat message, according to
                   packet field.
   

   :param payload: payload contained in the heartbeat message. Size can differ from
            payload_length, if payload_length and actual packet length disagree.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_encrypted_data

.. zeek:id:: ssl_plaintext_data
   :source-code: base/protocols/ssl/main.zeek 526 535

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, record_version: :zeek:type:`count`, content_type: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for SSL/TLS messages that are sent before full session encryption
   starts. Note that "full encryption" is a bit fuzzy, especially for TLSv1.3;
   here this event will be raised for early packets that are already using
   pre-encryption.  # This event is also used by Zeek internally to determine if
   the connection has been completely setup. This is necessary as TLS 1.3 does
   not have CCS anymore.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :param content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :param length: length of the entire message.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. zeek:id:: ssl_encrypted_data
   :source-code: policy/protocols/ssl/heartbleed.zeek 226 238

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, record_version: :zeek:type:`count`, content_type: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for SSL/TLS messages that are sent after session encryption
   started.
   
   Note that :zeek:id:`SSL::disable_analyzer_after_detection` has to be changed
   from its default to false for this event to be generated.
   
   Also note that, for DTLS 1.3, it is not always possible to give an exact length for
   the payload that is transported in the packet. If connection IDs are used, the length
   provided is the length of the entire packet, without the first byte (for the unified header).
   If no connection IDs are used, the length given is the actual payload length. Connection IDs
   are used with the connection ID extension in the client or server hello.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :param content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :param length: length of the encrypted payload in the record.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat ssl_probable_encrypted_handshake_message
      ssl_extension_connection_id

.. zeek:id:: ssl_probable_encrypted_handshake_message
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 700 700

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, length: :zeek:type:`count`)

   This event is generated for application data records of TLS 1.3 connections of which
   we suspect that they contain handshake messages.
   
   In TLS 1.3, large parts of the handshake are encrypted; the only cleartext packets
   typically exchanged are the client hello and the server hello. The first few packets
   after the client and server hello, however, are a continuation of the handshake and
   still include handshake data.
   
   This event is raised for these packets of which we suspect that they are handshake records,
   including the finished record.
   
   The heuristic for this is: all application data record after the server hello are
   handshake records until at least one application data record has been received
   from both the server and the client. Typically, the server will send more records
   before the client sends the first application data record; and the first application
   data record of the client will typically include the finished message.
   
   Given the encrypted nature of the protocol, in some cases this determination is
   not correct; the client can send more handshake packets before the finished message, e.g.,
   when client certificates are used.
   
   Note that :zeek:see::ssl_encrypted_data is also raised for these messages.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param length: length of the entire message.
   
   .. zeek:see::  ssl_client_hello ssl_established ssl_server_hello
      ssl_encrypted_data

.. zeek:id:: ssl_stapled_ocsp
   :source-code: policy/protocols/ssl/validate-ocsp.zeek 34 37

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, response: :zeek:type:`string`)

   This event contains the OCSP response contained in a Certificate Status Request
   message, when the client requested OCSP stapling and the server supports it.
   See description in :rfc:`6066`.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param response: OCSP data.

.. zeek:id:: ssl_handshake_message
   :source-code: base/protocols/ssl/main.zeek 364 446

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, msg_type: :zeek:type:`count`, length: :zeek:type:`count`)

   This event is raised for each unencrypted SSL/TLS handshake message.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param msg_type: Type of the handshake message that was seen.
   

   :param length: Length of the handshake message that was seen.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_change_cipher_spec ssl_connection_flipped ssl_certificate_request

.. zeek:id:: ssl_change_cipher_spec
   :source-code: base/bif/plugins/Zeek_SSL.events.bif.zeek 747 747

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`)

   This event is raised when a SSL/TLS ChangeCipherSpec message is encountered
   before encryption begins. Traffic will be encrypted following this message.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_handshake_message

.. zeek:id:: ssl_connection_flipped
   :source-code: base/protocols/ssl/main.zeek 357 362

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Zeek typically assumes that the originator of a connection is the client of the SSL/TLS
   session. In some scenarios this does not hold, and the responder of a connection is the
   client, and the initiator is the server.
   
   In these cases, Zeek raises this event. Connection direction is detected by looking at the
   server hello, client hello, and hello request handshake messages.
   

   :param c: The connection.
   
   .. zeek:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_handshake_message

.. zeek:id:: ssl_certificate_request
   :source-code: policy/protocols/ssl/certificate-request-info.zeek 13 23

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_client: :zeek:type:`bool`, certificate_types: :zeek:type:`index_vec`, supported_signature_algorithms: :zeek:type:`signature_and_hashalgorithm_vec`, certificate_authorities: :zeek:type:`string_vec`)

   This event is raised, when a Certificate Request handshake message is encountered. This
   Message can be used by a TLS server to request a client certificate.
   

   :param c: The connection.
   

   :param is_client: True if event is raised for the client side of the connection
              (the side that sends the client hello). This is typically equivalent
              with the originator, but does not have to be in all circumstances.
   

   :param certificate_types: List of the types of certificates that the client may offer.
   

   :param supported_signature_algorithms: List of hash/sighature algorithm pairs that the server
                                   supports, listed in descending order of preferences.
   

   :param certificate_authorities: List of distinguished names of certificate authorities that are
                            acceptable to the server. The individual entries are DER encoded.
                            :zeek:id:`parse_distinguished_name` can be used to decode the strings.
   
   .. zeek:see:: ssl_handshake_message x509_certificate ssl_server_hello ssl_client_hello
                 parse_distinguished_name

Functions
+++++++++

.. zeek:id:: set_ssl_established
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 13 13

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`) : :zeek:type:`bool`

   Sets if the SSL analyzer should consider the connection established (handshake
   finished successfully).
   

   :param c: The SSL connection.
   

   :returns: T on success, F on failure.

.. zeek:id:: set_secret
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, secret: :zeek:type:`string`) : :zeek:type:`bool`

   Set the secret that should be used to derive keys for the connection.
   (For TLS 1.2 this is the pre-master secret).
   

   :param c: The affected connection
   

   :param secret: secret to set
   

   :returns: T on success, F on failure.

.. zeek:id:: set_keys
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 35 35

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, keys: :zeek:type:`string`) : :zeek:type:`bool`

   Set the decryption keys that should be used to decrypt
   TLS application data in the connection.
   

   :param c: The affected connection
   

   :param keys: The key buffer as derived via TLS PRF.
   

   :returns: T on success, F on failure.

.. zeek:id:: parse_distinguished_name
   :source-code: base/bif/plugins/Zeek_SSL.functions.bif.zeek 46 46

   :Type: :zeek:type:`function` (dn: :zeek:type:`string`) : :zeek:type:`string`

   Decodes a DER-encoded distinguished name into an ASCII string,
   using the RFC2253 representation
   

   :param dn: DER encoded distinguished name
   

   :returns: Ascii representation on success, empty string on failure
   
   .. zeek:see:: ssl_certificate_request

.. _plugin-zeek-syslog:

Zeek::Syslog
------------

Syslog analyzer UDP-only

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_SYSLOG`

Events
++++++

.. zeek:id:: syslog_message
   :source-code: base/protocols/syslog/spicy-events.zeek 19 19

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, facility: :zeek:type:`count`, severity: :zeek:type:`count`, msg: :zeek:type:`string`)

   Generated for monitored Syslog messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Syslog>`__ for more
   information about the Syslog protocol.
   

   :param c: The connection record for the underlying transport-layer session/flow.
   

   :param facility: The "facility" included in the message.
   

   :param severity: The "severity" included in the message.
   

   :param msg: The message logged.
   
   .. note:: Zeek currently parses only UDP syslog traffic.

.. _plugin-zeek-tcp:

Zeek::TCP
---------

TCP analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_CONTENTLINE`

:zeek:enum:`Analyzer::ANALYZER_CONTENTS`

:zeek:enum:`Analyzer::ANALYZER_TCPSTATS`

Types
+++++

.. zeek:type:: TCP::Option
   :source-code: base/init-bare.zeek 394 421

   :Type: :zeek:type:`record`

      kind: :zeek:type:`count`
         The kind number associated with the option.  Other optional fields
         of this record may be set depending on this value.

      length: :zeek:type:`count`
         The total length of the option in bytes, including the kind byte and
         length byte (if present).

      data: :zeek:type:`string` :zeek:attr:`&optional`
         This field is set to the raw option bytes if the kind is not
         otherwise known/parsed.  It's also set for known kinds whose length
         was invalid.

      mss: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 2: Maximum Segment Size.

      window_scale: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 3: Window scale.

      sack: :zeek:type:`index_vec` :zeek:attr:`&optional`
         Kind 5: Selective ACKnowledgement (SACK).  This is a list of 2, 4,
         6, or 8 numbers with each consecutive pair being a 32-bit
         begin-pointer and 32-bit end pointer.

      send_timestamp: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 8: 4-byte sender timestamp value.

      echo_timestamp: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 8: 4-byte echo reply timestamp value.

      rate: :zeek:type:`count` :zeek:attr:`&optional`
         Kind 27: TCP Quick Start Response value.

      ttl_diff: :zeek:type:`count` :zeek:attr:`&optional`

      qs_nonce: :zeek:type:`count` :zeek:attr:`&optional`

   A TCP Option field parsed from a TCP header.

.. zeek:type:: TCP::OptionList
   :source-code: base/init-bare.zeek 424 424

   :Type: :zeek:type:`vector` of :zeek:type:`TCP::Option`

   The full list of TCP Option fields parsed from a TCP header.

Events
++++++

.. zeek:id:: new_connection_contents
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when reassembly starts for a TCP connection. This event is raised
   at the moment when Zeek's TCP analyzer enables stream reassembly for a
   connection.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected connection_reset connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection partial_connection

.. zeek:id:: connection_attempt
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 546 550

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for an unsuccessful connection attempt. This event is raised when
   an originator unsuccessfully attempted to establish a connection.
   "Unsuccessful" is defined as at least :zeek:id:`tcp_attempt_delay` seconds
   having elapsed since the originator first sent a connection establishment
   packet to the destination without seeing a reply.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_established
      connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_established
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 53 53

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when seeing a SYN-ACK packet from the responder in a TCP
   handshake.  An associated SYN packet was not seen from the originator
   side if its state is not set to :zeek:see:`TCP_ESTABLISHED`.
   The final ACK of the handshake in response to SYN-ACK may
   or may not occur later, one way to tell is to check the *history* field of
   :zeek:type:`connection` to see if the originator sent an ACK, indicated by
   'A' in the history string.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: partial_connection
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 540 544

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a new active TCP connection if Zeek did not see the initial
   handshake. This event is raised when Zeek has observed traffic from each
   endpoint, but the activity did not begin with the usual connection
   establishment.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected connection_reset connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection new_connection_contents
   

.. zeek:id:: connection_partial_close
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 87 87

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a previously inactive endpoint attempts to close a TCP
   connection via a normal FIN handshake or an abort RST sequence. When the
   endpoint sent one of these packets, Zeek waits
   :zeek:id:`tcp_partial_close_delay` prior to generating the event, to give
   the other endpoint a chance to close the connection normally.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK connection_half_finished connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_finished
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 101 101

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a TCP connection that finished normally. The event is raised
   when a regular FIN handshake from both endpoints was observed.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_half_finished
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 116 116

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when one endpoint of a TCP connection attempted to gracefully close
   the connection, but the other endpoint is in the TCP_INACTIVE state. This can
   happen due to split routing, in which Zeek only sees one side of a connection.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK  connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: connection_rejected
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 552 556

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a rejected TCP connection. This event is raised when an
   originator attempted to setup a TCP connection but the responder replied
   with a RST packet denying it.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending  connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      If the responder does not respond at all, :zeek:id:`connection_attempt` is
      raised instead. If the responder initially accepts the connection but
      aborts it later, Zeek first generates :zeek:id:`connection_established`
      and then :zeek:id:`connection_reset`.

.. zeek:id:: connection_reset
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 558 562

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when an endpoint aborted a TCP connection. The event is raised
   when one endpoint of an established TCP connection aborted by sending a RST
   packet.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected  connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection new_connection_contents
      partial_connection

.. zeek:id:: connection_pending
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 564 568

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for each still-open TCP connection when Zeek terminates.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection zeek_done

.. zeek:id:: connection_SYN_packet
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 191 191

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, pkt: :zeek:type:`SYN_packet`)

   Generated for a SYN packet. Zeek raises this event for every SYN packet seen
   by its TCP analyzer.
   

   :param c: The connection.
   

   :param pkt: Information extracted from the SYN packet.
   
   .. zeek:see:: connection_EOF  connection_attempt connection_established
      connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      This event has quite low-level semantics and can potentially be expensive
      to generate. It should only be used if one really needs the specific
      information passed into the handler via the ``pkt`` argument. If not,
      handling one of the other ``connection_*`` events is typically the
      better approach.

.. zeek:id:: connection_first_ACK
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 209 209

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for the first ACK packet seen for a TCP connection from
   its *originator*.
   

   :param c: The connection.
   
   .. zeek:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_finished
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      This event has quite low-level semantics and should be used only rarely.

.. zeek:id:: connection_EOF
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 226 226

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated at the end of reassembled TCP connections. The TCP reassembler
   raised the event once for each endpoint of a connection when it finished
   reassembling the corresponding side of the communication.
   

   :param c: The connection.
   

   :param is_orig: True if the event is raised for the originator side.
   
   .. zeek:see::  connection_SYN_packet connection_attempt connection_established
      connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. zeek:id:: tcp_packet
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 255 255

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, flags: :zeek:type:`string`, seq: :zeek:type:`count`, ack: :zeek:type:`count`, len: :zeek:type:`count`, payload: :zeek:type:`string`)

   Generated for every TCP packet. This is a very low-level and expensive event
   that should be avoided when at all possible. It's usually infeasible to
   handle when processing even medium volumes of traffic in real-time.  It's
   slightly better than :zeek:id:`new_packet` because it affects only TCP, but
   not much. That said, if you work from a trace and want to do some
   packet-level analysis, it may come in handy.
   

   :param c: The connection the packet is part of.
   

   :param is_orig: True if the packet was sent by the connection's originator.
   

   :param flags: A string with the packet's TCP flags. In the string, each character
          corresponds to one set flag, as follows: ``S`` -> SYN; ``F`` -> FIN;
          ``R`` -> RST; ``A`` -> ACK; ``P`` -> PUSH; ``U`` -> URGENT.
   

   :param seq: The packet's relative TCP sequence number.
   

   :param ack: If the ACK flag is set for the packet, the packet's relative ACK
        number, else zero.
   

   :param len: The length of the TCP payload, as specified in the packet header.
   

   :param payload: The raw TCP payload. Note that this may be shorter than *len* if
            the packet was not fully captured.
   
   .. zeek:see:: new_packet packet_contents tcp_option tcp_contents tcp_rexmit

.. zeek:id:: tcp_option
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 273 273

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, opt: :zeek:type:`count`, optlen: :zeek:type:`count`)

   Generated for each option found in a TCP header. Like many of the ``tcp_*``
   events, this is a very low-level event and potentially expensive as it may
   be raised very often.
   

   :param c: The connection the packet is part of.
   

   :param is_orig: True if the packet was sent by the connection's originator.
   

   :param opt: The numerical option number, as found in the TCP header.
   

   :param optlen: The length of the options value.
   
   .. zeek:see:: tcp_packet tcp_contents tcp_rexmit tcp_options
   
   .. note:: To inspect the actual option values, if any, use :zeek:see:`tcp_options`.

.. zeek:id:: tcp_options
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 286 286

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, options: :zeek:type:`TCP::OptionList`)

   Generated for each TCP header that contains TCP options.  This is a very
   low-level event and potentially expensive as it may be raised very often.
   

   :param c: The connection the packet is part of.
   

   :param is_orig: True if the packet was sent by the connection's originator.
   

   :param options: The list of options parsed out of the TCP header.
   
   .. zeek:see:: tcp_packet tcp_contents tcp_rexmit tcp_option

.. zeek:id:: tcp_contents
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 319 319

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, seq: :zeek:type:`count`, contents: :zeek:type:`string`)

   Generated for each chunk of reassembled TCP payload. When content delivery is
   enabled for a TCP connection (via :zeek:id:`tcp_content_delivery_ports_orig`,
   :zeek:id:`tcp_content_delivery_ports_resp`,
   :zeek:id:`tcp_content_deliver_all_orig`,
   :zeek:id:`tcp_content_deliver_all_resp`), this event is raised for each chunk
   of in-order payload reconstructed from the packet stream. Note that this
   event is potentially expensive if many connections carry significant amounts
   of data as then all that data needs to be passed on to the scripting layer.
   

   :param c: The connection the payload is part of.
   

   :param is_orig: True if the packet was sent by the connection's originator.
   

   :param seq: The sequence number corresponding to the first byte of the payload
        chunk.
   

   :param contents: The raw payload, which will be non-empty.
   
   .. zeek:see:: tcp_packet tcp_option tcp_rexmit
      tcp_content_delivery_ports_orig tcp_content_delivery_ports_resp
      tcp_content_deliver_all_resp tcp_content_deliver_all_orig
   
   .. note::
   
      The payload received by this event is the same that is also passed into
      application-layer protocol analyzers internally. Subsequent invocations of
      this event for the same connection receive non-overlapping in-order chunks
      of its TCP payload stream. It is however undefined what size each chunk
      has; while Zeek passes the data on as soon as possible, specifics depend on
      network-level effects such as latency, acknowledgements, reordering, etc.

.. zeek:id:: tcp_rexmit
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 337 337

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, seq: :zeek:type:`count`, len: :zeek:type:`count`, data_in_flight: :zeek:type:`count`, window: :zeek:type:`count`)

   Generated for each detected TCP segment retransmission.
   

   :param c: The connection the packet is part of.
   

   :param is_orig: True if the packet was sent by the connection's originator.
   

   :param seq: The segment's relative TCP sequence number.
   

   :param len: The length of the TCP segment, as specified in the packet header.
   

   :param data_in_flight: The number of bytes corresponding to the difference between
                   the last sequence number and last acknowledgement number
                   we've seen for a given endpoint.
   

   :param window: the TCP window size.

.. zeek:id:: tcp_multiple_checksum_errors
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 351 351

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a checksum-error threshold, per
   'C'/'c' history reporting.
   

   :param c: The connection record for the TCP connection.
   

   :param is_orig: True if the event is raised for the originator side.
   

   :param threshold: the threshold that was crossed
   
   .. zeek:see::  udp_multiple_checksum_errors
      tcp_multiple_zero_windows tcp_multiple_retransmissions tcp_multiple_gap

.. zeek:id:: tcp_multiple_zero_windows
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 364 364

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a zero-window threshold, per
   'W'/'w' history reporting.
   

   :param c: The connection record for the TCP connection.
   

   :param is_orig: True if the event is raised for the originator side.
   

   :param threshold: the threshold that was crossed
   
   .. zeek:see::  tcp_multiple_checksum_errors tcp_multiple_retransmissions tcp_multiple_gap

.. zeek:id:: tcp_multiple_retransmissions
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 377 377

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a retransmission threshold, per
   'T'/'t' history reporting.
   

   :param c: The connection record for the TCP connection.
   

   :param is_orig: True if the event is raised for the originator side.
   

   :param threshold: the threshold that was crossed
   
   .. zeek:see::  tcp_multiple_checksum_errors tcp_multiple_zero_windows tcp_multiple_gap

.. zeek:id:: tcp_multiple_gap
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 390 390

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, threshold: :zeek:type:`count`)

   Generated if a TCP flow crosses a gap threshold, per 'G'/'g' history
   reporting.
   

   :param c: The connection record for the TCP connection.
   

   :param is_orig: True if the event is raised for the originator side.
   

   :param threshold: the threshold that was crossed
   
   .. zeek:see::  tcp_multiple_checksum_errors tcp_multiple_zero_windows tcp_multiple_retransmissions

.. zeek:id:: contents_file_write_failure
   :source-code: base/bif/plugins/Zeek_TCP.events.bif.zeek 402 402

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`)

   Generated when failing to write contents of a TCP stream to a file.
   

   :param c: The connection whose contents are being recorded.
   

   :param is_orig: Which side of the connection encountered a failure to write.
   

   :param msg: A reason or description for the failure.
   
   .. zeek:see:: set_contents_file get_contents_file

Functions
+++++++++

.. zeek:id:: get_orig_seq
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 17 17

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`count`

   Get the originator sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :param cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's originator, or 0
            if *cid* does not point to an active TCP connection.
   
   .. zeek:see:: get_resp_seq

.. zeek:id:: get_resp_seq
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 30 30

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`) : :zeek:type:`count`

   Get the responder sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :param cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's responder, or 0
            if *cid* does not point to an active TCP connection.
   
   .. zeek:see:: get_orig_seq

.. zeek:id:: set_contents_file
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 64 64

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, direction: :zeek:type:`count`, f: :zeek:type:`file`) : :zeek:type:`bool`

   Associates a file handle with a connection for writing TCP byte stream
   contents.
   

   :param cid: The connection ID.
   

   :param direction: Controls what sides of the connection to record. The argument can
              take one of the four values:
   
              - ``CONTENTS_NONE``: Stop recording the connection's content.
              - ``CONTENTS_ORIG``: Record the data sent by the connection
                originator (often the client).
              - ``CONTENTS_RESP``: Record the data sent by the connection
                responder (often the server).
              - ``CONTENTS_BOTH``: Record the data sent in both directions.
                Results in the two directions being intermixed in the file,
                in the order the data was seen by Zeek.
   

   :param f: The file handle of the file to write the contents to.
   

   :returns: Returns false if *cid* does not point to an active connection, and
            true otherwise.
   
   .. note::
   
       The data recorded to the file reflects the byte stream, not the
       contents of individual packets. Reordering and duplicates are
       removed. If any data is missing, the recording stops at the
       missing data; this can happen, e.g., due to an
       :zeek:id:`content_gap` event.
   
   .. zeek:see:: get_contents_file set_record_packets contents_file_write_failure

.. zeek:id:: get_contents_file
   :source-code: base/bif/plugins/Zeek_TCP.functions.bif.zeek 80 80

   :Type: :zeek:type:`function` (cid: :zeek:type:`conn_id`, direction: :zeek:type:`count`) : :zeek:type:`file`

   Returns the file handle of the contents file of a connection.
   

   :param cid: The connection ID.
   

   :param direction: Controls what sides of the connection to record. See
              :zeek:id:`set_contents_file` for possible values.
   

   :returns: The :zeek:type:`file` handle for the contents file of the
            connection identified by *cid*. If the connection exists
            but there is no contents file for *direction*, then the function
            generates an error and returns a file handle to ``stderr``.
   
   .. zeek:see:: set_contents_file set_record_packets contents_file_write_failure

.. _plugin-zeek-websocket:

Zeek::WebSocket
---------------

WebSocket analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_WEBSOCKET`

Options/Constants
+++++++++++++++++

.. zeek:id:: WebSocket::payload_chunk_size
   :source-code: base/init-bare.zeek 468 468

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``8192``

   The WebSocket analyzer consumes and forwards
   frame payload in chunks to keep memory usage
   bounded. There should not be a reason to change
   this value except for debugging and
   testing reasons.

Types
+++++

.. zeek:type:: WebSocket::AnalyzerConfig
   :source-code: base/init-bare.zeek 483 499

   :Type: :zeek:type:`record`

      analyzer: :zeek:type:`Analyzer::Tag` :zeek:attr:`&optional`
         The analyzer to attach for analysis of the WebSocket
         frame payload. See *use_dpd* below for the behavior
         when unset.

      use_dpd: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`WebSocket::use_dpd_default` :zeek:attr:`&optional`
         If *analyzer* is unset, determines whether to attach a
         PIA_TCP analyzer for dynamic protocol detection with
         WebSocket payload.

      subprotocol: :zeek:type:`string` :zeek:attr:`&optional`
         The subprotocol as selected by the server, if any.

      server_extensions: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional`
         The WebSocket extensions as selected by the server, if any.

   Record type that is passed to :zeek:see:`WebSocket::configure_analyzer`.
   
   This record allows to configure the WebSocket analyzer given
   parameters collected from HTTP headers.

Events
++++++

.. zeek:id:: websocket_established
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 11 11

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, aid: :zeek:type:`count`)

   Generated when a WebSocket handshake completed.
   

   :param c: The WebSocket connection.
   

   :param aid: The analyzer identifier of the WebSocket analyzer.
   
   .. zeek:see:: WebSocket::__configure_analyzer WebSocket::configure_analyzer

.. zeek:id:: websocket_frame
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 28 28

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, fin: :zeek:type:`bool`, rsv: :zeek:type:`count`, opcode: :zeek:type:`count`, payload_len: :zeek:type:`count`)

   Generated for every WebSocket frame.
   

   :param c: The WebSocket connection.
   

   :param is_orig: True if the frame is from the originator, else false.
   

   :param fin: True if the fin bit is set, else false.
   

   :param rsv: The value of the RSV1, RSV2 and RSV3 bits.
   

   :param opcode: The frame's opcode.
   

   :param payload_len: The frame's payload length.
   

.. zeek:id:: websocket_frame_data
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 45 45

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for every chunk of WebSocket frame payload data.
   
   Do not use it to extract data from a WebSocket connection unless for testing
   or experimentation. Consider implementing a proper analyzer instead.
   

   :param c: The WebSocket connection.
   

   :param is_orig: True if the frame is from the originator, else false.
   

   :param data: One data chunk of frame payload. The length of is at most
         :zeek:see:`WebSocket::payload_chunk_size` bytes. A frame with
         a longer payload will result in multiple events events.
   
   .. zeek:see:: WebSocket::payload_chunk_size

.. zeek:id:: websocket_message
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, opcode: :zeek:type:`count`)

   Generated for every completed WebSocket message.
   

   :param c: The WebSocket connection.
   

   :param is_orig: True if the frame is from the originator, else false.
   

   :param opcode: The first frame's opcode.

.. zeek:id:: websocket_close
   :source-code: base/bif/plugins/Zeek_WebSocket.events.bif.zeek 72 72

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, status: :zeek:type:`count`, reason: :zeek:type:`string`)

   Generated for WebSocket Close frames.
   

   :param c: The WebSocket connection.
   

   :param is_orig: True if the frame is from the originator, else false.
   

   :param status: If the CloseFrame had no payload, this is 0, otherwise the value
           of the first two bytes in the frame's payload.
   

   :param reason: Remaining payload after *status*. This is capped at
           2 bytes less than :zeek:see:`WebSocket::payload_chunk_size`.
   
   .. zeek:see:: WebSocket::payload_chunk_size

Functions
+++++++++

.. zeek:id:: WebSocket::__configure_analyzer
   :source-code: base/bif/plugins/Zeek_WebSocket.functions.bif.zeek 24 24

   :Type: :zeek:type:`function` (c: :zeek:type:`connection`, aid: :zeek:type:`count`, config: :zeek:type:`WebSocket::AnalyzerConfig`) : :zeek:type:`bool`

   Configure the WebSocket analyzer.
   
   Called during :zeek:see:`websocket_established` to configure
   the WebSocket analyzer given the selected protocol and extension
   as chosen by the server.
   

   :param c: The WebSocket connection.

   :param aid: The identifier for the WebSocket analyzer as provided to :zeek:see:`websocket_established`.
   

   :param server_protocol: The protocol as found in the server's Sec-WebSocket-Protocol HTTP header, or empty.
   

   :param server_extensions: The extension as selected by the server via the Sec-WebSocket-Extensions HTTP Header.
   
   .. zeek:see:: websocket_established

.. _plugin-zeek-xmpp:

Zeek::XMPP
----------

XMPP analyzer (StartTLS only)

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_XMPP`

Events
++++++

.. zeek:id:: xmpp_starttls
   :source-code: base/bif/plugins/Zeek_XMPP.events.bif.zeek 8 8

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated when a XMPP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :param c: The connection.

.. _plugin-zeek-zip:

Zeek::ZIP
---------

Generic ZIP support analyzer

Components
++++++++++

:zeek:enum:`Analyzer::ANALYZER_ZIP`

