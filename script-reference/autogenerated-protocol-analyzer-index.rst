Protocol Analyzers
==================

.. bro:type:: Analyzer::Tag

   :Type: :bro:type:`enum`

      .. bro:enum:: Analyzer::ANALYZER_AYIYA Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_BACKDOOR Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_BITTORRENT Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_BITTORRENTTRACKER Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONNSIZE Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_DCE_RPC Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_DHCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_DNP3_TCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_DNP3_UDP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_DNS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_DNS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_FTP_DATA Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_IRC_DATA Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_FINGER Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_FTP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_FTP_ADAT Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_GNUTELLA Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_GSSAPI Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_GTPV1 Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_HTTP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_ICMP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_IDENT Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_IMAP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_INTERCONN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_IRC Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_KRB Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_KRB_TCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_RLOGIN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_RSH Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_LOGIN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_NVT Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_RLOGIN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_RSH Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_TELNET Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_MODBUS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_MYSQL Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_NCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_NCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_NETBIOSSSN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_NETBIOSSSN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_NTLM Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_NTP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_PIA_TCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_PIA_UDP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_POP3 Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_RADIUS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_RDP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_RFB Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_NFS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_RPC Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_MOUNT Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_NFS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_PORTMAPPER Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SIP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS_SMB Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SMB Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SMTP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SNMP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SOCKS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SSH Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_DTLS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SSL Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_STEPPINGSTONE Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_SYSLOG Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTLINE Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_CONTENTS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_TCP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_TCPSTATS Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_TEREDO Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_UDP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_VXLAN Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_XMPP Analyzer::Tag

      .. bro:enum:: Analyzer::ANALYZER_ZIP Analyzer::Tag

Bro::ARP
--------

ARP Parsing

Components
++++++++++

Events
++++++

.. bro:id:: arp_request

   :Type: :bro:type:`event` (mac_src: :bro:type:`string`, mac_dst: :bro:type:`string`, SPA: :bro:type:`addr`, SHA: :bro:type:`string`, TPA: :bro:type:`addr`, THA: :bro:type:`string`)

   Generated for ARP requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The request's source MAC address.
   

   :mac_dst: The request's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. bro:see:: arp_reply  bad_arp

.. bro:id:: arp_reply

   :Type: :bro:type:`event` (mac_src: :bro:type:`string`, mac_dst: :bro:type:`string`, SPA: :bro:type:`addr`, SHA: :bro:type:`string`, TPA: :bro:type:`addr`, THA: :bro:type:`string`)

   Generated for ARP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Address_Resolution_Protocol>`__
   for more information about the ARP protocol.
   

   :mac_src: The reply's source MAC address.
   

   :mac_dst: The reply's destination MAC address.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   
   .. bro:see::  arp_request bad_arp

.. bro:id:: bad_arp

   :Type: :bro:type:`event` (SPA: :bro:type:`addr`, SHA: :bro:type:`string`, TPA: :bro:type:`addr`, THA: :bro:type:`string`, explanation: :bro:type:`string`)

   Generated for ARP packets that Bro cannot interpret. Examples are packets
   with non-standard hardware address formats or hardware addresses that do not
   match the originator of the packet.
   

   :SPA: The sender protocol address.
   

   :SHA: The sender hardware address.
   

   :TPA: The target protocol address.
   

   :THA: The target hardware address.
   

   :explanation: A short description of why the ARP packet is considered "bad".
   
   .. bro:see:: arp_reply arp_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::AYIYA
----------

AYIYA Analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_AYIYA`

Bro::BackDoor
-------------

Backdoor Analyzer deprecated

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_BACKDOOR`

Events
++++++

.. bro:id:: backdoor_stats

   :Type: :bro:type:`event` (c: :bro:type:`connection`, os: :bro:type:`backdoor_endp_stats`, rs: :bro:type:`backdoor_endp_stats`)

   Deprecated. Will be removed.

.. bro:id:: backdoor_remove_conn

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: ftp_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: gnutella_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: http_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: irc_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: telnet_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, len: :bro:type:`count`)

   Deprecated. Will be removed.

.. bro:id:: ssh_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Deprecated. Will be removed.

.. bro:id:: rlogin_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, num_null: :bro:type:`count`, len: :bro:type:`count`)

   Deprecated. Will be removed.

.. bro:id:: smtp_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

.. bro:id:: http_proxy_signature_found

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

Bro::BitTorrent
---------------

BitTorrent Analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_BITTORRENT`

:bro:enum:`Analyzer::ANALYZER_BITTORRENTTRACKER`

Events
++++++

.. bro:id:: bittorrent_peer_handshake

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, reserved: :bro:type:`string`, info_hash: :bro:type:`string`, peer_id: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_have bittorrent_peer_interested bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_keep_alive

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_choke

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. bro:id:: bittorrent_peer_unchoke

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request
      bittorrent_peer_unknown bittorrent_peer_weird

.. bro:id:: bittorrent_peer_interested

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_not_interested

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive  bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_have

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, piece_index: :bro:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake  bittorrent_peer_interested bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_bitfield

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, bitfield: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see::  bittorrent_peer_cancel bittorrent_peer_choke bittorrent_peer_handshake
      bittorrent_peer_have bittorrent_peer_interested bittorrent_peer_keep_alive
      bittorrent_peer_not_interested bittorrent_peer_piece bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, index: :bro:type:`count`, begin: :bro:type:`count`, length: :bro:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port  bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_piece

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, index: :bro:type:`count`, begin: :bro:type:`count`, piece_length: :bro:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_port
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_cancel

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, index: :bro:type:`count`, begin: :bro:type:`count`, length: :bro:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield  bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. bro:id:: bittorrent_peer_port

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, listen_port: :bro:type:`port`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_request bittorrent_peer_unchoke bittorrent_peer_unknown
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_unknown

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, message_id: :bro:type:`count`, data: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_weird

.. bro:id:: bittorrent_peer_weird

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown

.. bro:id:: bt_tracker_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, uri: :bro:type:`string`, headers: :bro:type:`bt_tracker_headers`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. bro:id:: bt_tracker_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, status: :bro:type:`count`, headers: :bro:type:`bt_tracker_headers`, peers: :bro:type:`bittorrent_peer_set`, benc: :bro:type:`bittorrent_benc_dir`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. bro:id:: bt_tracker_response_not_ok

   :Type: :bro:type:`event` (c: :bro:type:`connection`, status: :bro:type:`count`, headers: :bro:type:`bt_tracker_headers`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

.. bro:id:: bt_tracker_weird

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/BitTorrent_(protocol)>`__ for
   more information about the BitTorrent protocol.
   
   .. bro:see:: bittorrent_peer_bitfield bittorrent_peer_cancel bittorrent_peer_choke
      bittorrent_peer_handshake bittorrent_peer_have bittorrent_peer_interested
      bittorrent_peer_keep_alive bittorrent_peer_not_interested bittorrent_peer_piece
      bittorrent_peer_port bittorrent_peer_request bittorrent_peer_unchoke
      bittorrent_peer_unknown bittorrent_peer_weird

Bro::ConnSize
-------------

Connection size analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONNSIZE`

Events
++++++

.. bro:id:: conn_bytes_threshold_crossed

   :Type: :bro:type:`event` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`)

   Generated for a connection that crossed a set byte threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   ConnThreshold::bytes_threshold_crossed instead.
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: true if the threshold was crossed by the originator of the connection
   
   .. bro:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

.. bro:id:: conn_packets_threshold_crossed

   :Type: :bro:type:`event` (c: :bro:type:`connection`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`)

   Generated for a connection that crossed a set packet threshold. Note that this
   is a low level event that should usually be avoided for user code. Use
   ConnThreshold::bytes_threshold_crossed instead.
   

   :c: the connection
   

   :threshold: the threshold that was set
   

   :is_orig: true if the threshold was crossed by the originator of the connection
   
   .. bro:see:: set_current_conn_packets_threshold set_current_conn_bytes_threshold conn_bytes_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

Functions
+++++++++

.. bro:id:: set_current_conn_bytes_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Sets the current byte threshold for connection sizes, overwriting any potential old
   threshold. Be aware that in nearly any case you will want to use the high level API
   instead (ConnThreshold::set_bytes_threshold).
   

   :cid: The connection id.
   

   :threshold: Threshold in bytes.
   

   :is_orig: If true, threshold is set for bytes from originator, otherwhise for bytes from responder.
   
   .. bro:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

.. bro:id:: set_current_conn_packets_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, threshold: :bro:type:`count`, is_orig: :bro:type:`bool`) : :bro:type:`bool`

   Sets a threshold for connection packets, overwtiting any potential old thresholds.
   Be aware that in nearly any case you will want to use the high level API
   instead (ConnThreshold::set_packets_threshold).
   

   :cid: The connection id.
   

   :threshold: Threshold in packets.
   

   :is_orig: If true, threshold is set for packets from originator, otherwhise for packets from responder.
   
   .. bro:see:: set_current_conn_bytes_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_bytes_threshold get_current_conn_packets_threshold

.. bro:id:: get_current_conn_bytes_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, is_orig: :bro:type:`bool`) : :bro:type:`count`

   Gets the current byte threshold size for a connection.
   

   :cid: The connection id.
   

   :is_orig: If true, threshold of originator, otherwhise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in bytes
   
   .. bro:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_packets_threshold

.. bro:id:: get_current_conn_packets_threshold

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, is_orig: :bro:type:`bool`) : :bro:type:`count`

   Gets the current packet threshold size for a connection.
   

   :cid: The connection id.
   

   :is_orig: If true, threshold of originator, otherwhise threshold of responder.
   

   :returns: 0 if no threshold is set or the threshold in packets
   
   .. bro:see:: set_current_conn_packets_threshold conn_bytes_threshold_crossed conn_packets_threshold_crossed
                get_current_conn_bytes_threshold

Bro::DCE_RPC
------------

DCE-RPC analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_DCE_RPC`

Options/Constants
+++++++++++++++++

.. bro:id:: DCE_RPC::max_cmd_reassembly

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``20``

   The maximum number of simultaneous fragmented commands that
   the DCE_RPC analyzer will tolerate before the it will generate
   a weird and skip further input.

.. bro:id:: DCE_RPC::max_frag_data

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``30000``

   The maximum number of fragmented bytes that the DCE_RPC analyzer
   will tolerate on a command before the analyzer will generate a weird
   and skip further input.

Types
+++++

.. bro:type:: DCE_RPC::PType

   :Type: :bro:type:`enum`

      .. bro:enum:: DCE_RPC::REQUEST DCE_RPC::PType

      .. bro:enum:: DCE_RPC::PING DCE_RPC::PType

      .. bro:enum:: DCE_RPC::RESPONSE DCE_RPC::PType

      .. bro:enum:: DCE_RPC::FAULT DCE_RPC::PType

      .. bro:enum:: DCE_RPC::WORKING DCE_RPC::PType

      .. bro:enum:: DCE_RPC::NOCALL DCE_RPC::PType

      .. bro:enum:: DCE_RPC::REJECT DCE_RPC::PType

      .. bro:enum:: DCE_RPC::ACK DCE_RPC::PType

      .. bro:enum:: DCE_RPC::CL_CANCEL DCE_RPC::PType

      .. bro:enum:: DCE_RPC::FACK DCE_RPC::PType

      .. bro:enum:: DCE_RPC::CANCEL_ACK DCE_RPC::PType

      .. bro:enum:: DCE_RPC::BIND DCE_RPC::PType

      .. bro:enum:: DCE_RPC::BIND_ACK DCE_RPC::PType

      .. bro:enum:: DCE_RPC::BIND_NAK DCE_RPC::PType

      .. bro:enum:: DCE_RPC::ALTER_CONTEXT DCE_RPC::PType

      .. bro:enum:: DCE_RPC::ALTER_CONTEXT_RESP DCE_RPC::PType

      .. bro:enum:: DCE_RPC::AUTH3 DCE_RPC::PType

      .. bro:enum:: DCE_RPC::SHUTDOWN DCE_RPC::PType

      .. bro:enum:: DCE_RPC::CO_CANCEL DCE_RPC::PType

      .. bro:enum:: DCE_RPC::ORPHANED DCE_RPC::PType

      .. bro:enum:: DCE_RPC::RTS DCE_RPC::PType


.. bro:type:: DCE_RPC::IfID

   :Type: :bro:type:`enum`

      .. bro:enum:: DCE_RPC::unknown_if DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::epmapper DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::lsarpc DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::lsa_ds DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::mgmt DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::netlogon DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::samr DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::srvsvc DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::spoolss DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::drs DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::winspipe DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::wkssvc DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::oxid DCE_RPC::IfID

      .. bro:enum:: DCE_RPC::ISCMActivator DCE_RPC::IfID


Events
++++++

.. bro:id:: dce_rpc_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, fid: :bro:type:`count`, ptype_id: :bro:type:`count`, ptype: :bro:type:`DCE_RPC::PType`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` message.
   

   :c: The connection.
   

   :is_orig: True if the message was sent by the originator of the TCP connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ptype_id: Numeric representation of the procedure type of the message.
   

   :ptype: Enum representation of the prodecure type of the message.
   
   .. bro:see:: dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. bro:id:: dce_rpc_bind

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, uuid: :bro:type:`string`, ver_major: :bro:type:`count`, ver_minor: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :uuid: The string interpretted uuid of the endpoint being requested.
   

   :ver_major: The major version of the endpoint being requested.
   

   :ver_minor: The minor version of the endpoint being requested.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind_ack dce_rpc_request dce_rpc_response

.. bro:id:: dce_rpc_alter_context

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, uuid: :bro:type:`string`, ver_major: :bro:type:`count`, ver_minor: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context request message.
   Since RPC offers the ability for a client to request connections to multiple endpoints, this event can occur
   multiple times for a single RPC message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :uuid: The string interpretted uuid of the endpoint being requested.
   

   :ver_major: The major version of the endpoint being requested.
   

   :ver_minor: The minor version of the endpoint being requested.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context_resp

.. bro:id:: dce_rpc_bind_ack

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, sec_addr: :bro:type:`string`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` bind request ack message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :sec_addr: Secondary address for the ack.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_request dce_rpc_response

.. bro:id:: dce_rpc_alter_context_resp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` alter context response message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request dce_rpc_response dce_rpc_alter_context

.. bro:id:: dce_rpc_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, opnum: :bro:type:`count`, stub_len: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` request message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.
   

   :opnum: Number of the RPC operation.
   

   :stub_len: Length of the data for the request.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_response

.. bro:id:: dce_rpc_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, fid: :bro:type:`count`, ctx_id: :bro:type:`count`, opnum: :bro:type:`count`, stub_len: :bro:type:`count`)

   Generated for every :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` response message.
   

   :c: The connection.
   

   :fid: File ID of the PIPE that carried the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)`
        message. Zero will be used if the :abbr:`DCE-RPC (Distributed Computing Environment/Remote Procedure Calls)` was
        not transported over a pipe.
   

   :ctx_id: The context identifier of the data representation.

   :opnum: Number of the RPC operation.
   

   :stub_len: Length of the data for the response.
   
   .. bro:see:: dce_rpc_message dce_rpc_bind dce_rpc_bind_ack dce_rpc_request

Bro::DHCP
---------

DHCP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_DHCP`

Types
+++++

.. bro:type:: DHCP::Msg

   :Type: :bro:type:`record`

      op: :bro:type:`count`
         Message OP code. 1 = BOOTREQUEST, 2 = BOOTREPLY

      m_type: :bro:type:`count`
         The type of DHCP message.

      xid: :bro:type:`count`
         Transaction ID of a DHCP session.

      secs: :bro:type:`interval`
         Number of seconds since client began address acquisition
         or renewal process

      flags: :bro:type:`count`

      ciaddr: :bro:type:`addr`
         Original IP address of the client.

      yiaddr: :bro:type:`addr`
         IP address assigned to the client.

      siaddr: :bro:type:`addr`
         IP address of the server.

      giaddr: :bro:type:`addr`
         IP address of the relaying gateway.

      chaddr: :bro:type:`string`
         Client hardware address.

      sname: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         Server host name.

      file_n: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`
         Boot file name.

   A DHCP message.
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::Addrs

   :Type: :bro:type:`vector` of :bro:type:`addr`

   A list of addresses offered by a DHCP server.  Could be routers,
   DNS servers, or other.
   
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::SubOpt

   :Type: :bro:type:`record`

      code: :bro:type:`count`

      value: :bro:type:`string`

   DHCP Relay Agent Information Option (Option 82)
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::SubOpts

   :Type: :bro:type:`vector` of :bro:type:`DHCP::SubOpt`


.. bro:type:: DHCP::ClientFQDN

   :Type: :bro:type:`record`

      flags: :bro:type:`count`
         An unparsed bitfield of flags (refer to RFC 4702).

      rcode1: :bro:type:`count`
         This field is deprecated in the standard.

      rcode2: :bro:type:`count`
         This field is deprecated in the standard.

      domain_name: :bro:type:`string`
         The Domain Name part of the option carries all or part of the FQDN
         of a DHCP client.

   DHCP Client FQDN Option information (Option 81)

.. bro:type:: DHCP::ClientID

   :Type: :bro:type:`record`

      hwtype: :bro:type:`count`

      hwaddr: :bro:type:`string`

   DHCP Client Identifier (Option 61)
   .. bro:see:: dhcp_message

.. bro:type:: DHCP::Options

   :Type: :bro:type:`record`

      options: :bro:type:`index_vec` :bro:attr:`&optional`
         The ordered list of all DHCP option numbers.

      subnet_mask: :bro:type:`addr` :bro:attr:`&optional`
         Subnet Mask Value (option 1)

      routers: :bro:type:`DHCP::Addrs` :bro:attr:`&optional`
         Router addresses (option 3)

      dns_servers: :bro:type:`DHCP::Addrs` :bro:attr:`&optional`
         DNS Server addresses (option 6)

      host_name: :bro:type:`string` :bro:attr:`&optional`
         The Hostname of the client (option 12)

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The DNS domain name of the client (option 15)

      forwarding: :bro:type:`bool` :bro:attr:`&optional`
         Enable/Disable IP Forwarding (option 19)

      broadcast: :bro:type:`addr` :bro:attr:`&optional`
         Broadcast Address (option 28)

      vendor: :bro:type:`string` :bro:attr:`&optional`
         Vendor specific data. This can frequently
         be unparsed binary data. (option 43)

      nbns: :bro:type:`DHCP::Addrs` :bro:attr:`&optional`
         NETBIOS name server list (option 44)

      addr_request: :bro:type:`addr` :bro:attr:`&optional`
         Address requested by the client (option 50)

      lease: :bro:type:`interval` :bro:attr:`&optional`
         Lease time offered by the server. (option 51)

      serv_addr: :bro:type:`addr` :bro:attr:`&optional`
         Server address to allow clients to distinguish
         between lease offers. (option 54)

      param_list: :bro:type:`index_vec` :bro:attr:`&optional`
         DHCP Parameter Request list (option 55)

      message: :bro:type:`string` :bro:attr:`&optional`
         Textual error message (option 56)

      max_msg_size: :bro:type:`count` :bro:attr:`&optional`
         Maximum Message Size (option 57)

      renewal_time: :bro:type:`interval` :bro:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         RENEWING state. (option 58)

      rebinding_time: :bro:type:`interval` :bro:attr:`&optional`
         This option specifies the time interval from address
         assignment until the client transitions to the
         REBINDING state. (option 59)

      vendor_class: :bro:type:`string` :bro:attr:`&optional`
         This option is used by DHCP clients to optionally
         identify the vendor type and configuration of a DHCP
         client. (option 60)

      client_id: :bro:type:`DHCP::ClientID` :bro:attr:`&optional`
         DHCP Client Identifier (Option 61)

      user_class: :bro:type:`string` :bro:attr:`&optional`
         User Class opaque value (Option 77)

      client_fqdn: :bro:type:`DHCP::ClientFQDN` :bro:attr:`&optional`
         DHCP Client FQDN (Option 81)

      sub_opt: :bro:type:`DHCP::SubOpts` :bro:attr:`&optional`
         DHCP Relay Agent Information Option (Option 82)

      auto_config: :bro:type:`bool` :bro:attr:`&optional`
         Auto Config option to let host know if it's allowed to
         auto assign an IP address. (Option 116)

      auto_proxy_config: :bro:type:`string` :bro:attr:`&optional`
         URL to find a proxy.pac for auto proxy config (Option 252)


Events
++++++

.. bro:id:: dhcp_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`DHCP::Msg`, options: :bro:type:`DHCP::Options`)

   Generated for all DHCP messages.
   

   :c: The connection record describing the underlying UDP flow.
   

   :is_orig: Indicate if the message came in a packet from the
           originator/client of the udp flow or the responder/server.
   

   :msg: The parsed type-independent part of the DHCP message. The message
        type is indicated in this record.
   

   :options: The full set of supported and parsed DHCP options.

Bro::DNP3
---------

DNP3 UDP/TCP analyzers

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_DNP3_TCP`

:bro:enum:`Analyzer::ANALYZER_DNP3_UDP`

Events
++++++

.. bro:id:: dnp3_application_request_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, application: :bro:type:`count`, fc: :bro:type:`count`)

   Generated for a DNP3 request header.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :fc: function code.
   

.. bro:id:: dnp3_application_response_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, application: :bro:type:`count`, fc: :bro:type:`count`, iin: :bro:type:`count`)

   Generated for a DNP3 response header.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :fc: function code.
   

   :iin: internal indication number.
   

.. bro:id:: dnp3_object_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, obj_type: :bro:type:`count`, qua_field: :bro:type:`count`, number: :bro:type:`count`, rf_low: :bro:type:`count`, rf_high: :bro:type:`count`)

   Generated for the object header found in both DNP3 requests and responses.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :obj_type: type of object, which is classified based on an 8-bit group number
             and an 8-bit variation number.
   

   :qua_field: qualifier field.
   

   :number: TODO.
   

   :rf_low: the structure of the range field depends on the qualified field.
           In some cases, the range field contains only one logic part, e.g.,
           number of objects, so only *rf_low* contains useful values.
   

   :rf_high: in some cases, the range field contains two logic parts, e.g., start
            index and stop index, so *rf_low* contains the start index
            while *rf_high* contains the stop index.
   

.. bro:id:: dnp3_object_prefix

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix_value: :bro:type:`count`)

   Generated for the prefix before a DNP3 object. The structure and the meaning
   of the prefix are defined by the qualifier field.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :prefix_value: The prefix.
   

.. bro:id:: dnp3_header_block

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, len: :bro:type:`count`, ctrl: :bro:type:`count`, dest_addr: :bro:type:`count`, src_addr: :bro:type:`count`)

   Generated for an additional header that the DNP3 analyzer passes to the
   script-level. This header mimics the DNP3 transport-layer yet is only passed
   once for each sequence of DNP3 records (which are otherwise reassembled and
   treated as a single entity).
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :len:   the "length" field in the DNP3 Pseudo Link Layer.
   

   :ctrl:  the "control" field in the DNP3 Pseudo Link Layer.
   

   :dest_addr: the "destination" field in the DNP3 Pseudo Link Layer.
   

   :src_addr: the "source" field in the DNP3 Pseudo Link Layer.
   

.. bro:id:: dnp3_response_data_object

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data_value: :bro:type:`count`)

   Generated for a DNP3 "Response_Data_Object".
   The "Response_Data_Object" contains two parts: object prefix and object
   data. In most cases, object data are defined by new record types. But
   in a few cases, object data are directly basic types, such as int16, or
   int8; thus we use an additional *data_value* to record the values of those
   object data.
   

   :c: The connection the DNP3 communication is part of.
   

   :is_orig: True if this reflects originator-side activity.
   

   :data_value: The value for those objects that carry their information here
               directly.
   

.. bro:id:: dnp3_attribute_common

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data_type_code: :bro:type:`count`, leng: :bro:type:`count`, attribute_obj: :bro:type:`string`)

   Generated for DNP3 attributes.

.. bro:id:: dnp3_crob

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, control_code: :bro:type:`count`, count8: :bro:type:`count`, on_time: :bro:type:`count`, off_time: :bro:type:`count`, status_code: :bro:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 1

   :CROB: control relay output block

.. bro:id:: dnp3_pcb

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, control_code: :bro:type:`count`, count8: :bro:type:`count`, on_time: :bro:type:`count`, off_time: :bro:type:`count`, status_code: :bro:type:`count`)

   Generated for DNP3 objects with the group number 12 and variation number 2

   :PCB: Pattern Control Block

.. bro:id:: dnp3_counter_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 1
   counter 32 bit with flag

.. bro:id:: dnp3_counter_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 2
   counter 16 bit with flag

.. bro:id:: dnp3_counter_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 5
   counter 32 bit without flag

.. bro:id:: dnp3_counter_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 20 and variation number 6
   counter 16 bit without flag

.. bro:id:: dnp3_frozen_counter_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 1
   frozen counter 32 bit with flag

.. bro:id:: dnp3_frozen_counter_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 2
   frozen counter 16 bit with flag

.. bro:id:: dnp3_frozen_counter_32wFlagTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 5
   frozen counter 32 bit with flag and time

.. bro:id:: dnp3_frozen_counter_16wFlagTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, count_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 6
   frozen counter 16 bit with flag and time

.. bro:id:: dnp3_frozen_counter_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 9
   frozen counter 32 bit without flag

.. bro:id:: dnp3_frozen_counter_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, count_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 21 and variation number 10
   frozen counter 16 bit without flag

.. bro:id:: dnp3_analog_input_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 1
   analog input 32 bit with flag

.. bro:id:: dnp3_analog_input_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 2
   analog input 16 bit with flag

.. bro:id:: dnp3_analog_input_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 3
   analog input 32 bit without flag

.. bro:id:: dnp3_analog_input_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 4
   analog input 16 bit without flag

.. bro:id:: dnp3_analog_input_SPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 5
   analog input single precision, float point with flag

.. bro:id:: dnp3_analog_input_DPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value_low: :bro:type:`count`, value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 30 and variation number 6
   analog input double precision, float point with flag

.. bro:id:: dnp3_frozen_analog_input_32wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 1
   frozen analog input 32 bit with flag

.. bro:id:: dnp3_frozen_analog_input_16wFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 2
   frozen analog input 16 bit with flag

.. bro:id:: dnp3_frozen_analog_input_32wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 3
   frozen analog input 32 bit with time-of-freeze

.. bro:id:: dnp3_frozen_analog_input_16wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 4
   frozen analog input 16 bit with time-of-freeze

.. bro:id:: dnp3_frozen_analog_input_32woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 5
   frozen analog input 32 bit without flag

.. bro:id:: dnp3_frozen_analog_input_16woFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 6
   frozen analog input 16 bit without flag

.. bro:id:: dnp3_frozen_analog_input_SPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 7
   frozen analog input single-precision, float point with flag

.. bro:id:: dnp3_frozen_analog_input_DPwFlag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value_low: :bro:type:`count`, frozen_value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 31 and variation number 8
   frozen analog input double-precision, float point with flag

.. bro:id:: dnp3_analog_input_event_32woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 1
   analog input event 32 bit without time

.. bro:id:: dnp3_analog_input_event_16woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 2
   analog input event 16 bit without time

.. bro:id:: dnp3_analog_input_event_32wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 3
   analog input event 32 bit with time

.. bro:id:: dnp3_analog_input_event_16wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 4
   analog input event 16 bit with time

.. bro:id:: dnp3_analog_input_event_SPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 5
   analog input event single-precision float point without time

.. bro:id:: dnp3_analog_input_event_DPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value_low: :bro:type:`count`, value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 6
   analog input event double-precision float point without time

.. bro:id:: dnp3_analog_input_event_SPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 7
   analog input event single-precision float point with time

.. bro:id:: dnp3_analog_input_event_DPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, value_low: :bro:type:`count`, value_high: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 32 and variation number 8
   analog input event double-precisiion float point with time

.. bro:id:: dnp3_frozen_analog_input_event_32woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 1
   frozen analog input event 32 bit without time

.. bro:id:: dnp3_frozen_analog_input_event_16woTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 2
   frozen analog input event 16 bit without time

.. bro:id:: dnp3_frozen_analog_input_event_32wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 3
   frozen analog input event 32 bit with time

.. bro:id:: dnp3_frozen_analog_input_event_16wTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 4
   frozen analog input event 16 bit with time

.. bro:id:: dnp3_frozen_analog_input_event_SPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 5
   frozen analog input event single-precision float point without time

.. bro:id:: dnp3_frozen_analog_input_event_DPwoTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value_low: :bro:type:`count`, frozen_value_high: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 6
   frozen analog input event double-precision float point without time

.. bro:id:: dnp3_frozen_analog_input_event_SPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 33 and variation number 7
   frozen analog input event single-precision float point with time

.. bro:id:: dnp3_frozen_analog_input_event_DPwTime

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flag: :bro:type:`count`, frozen_value_low: :bro:type:`count`, frozen_value_high: :bro:type:`count`, time48: :bro:type:`count`)

   Generated for DNP3 objects with the group number 34 and variation number 8
   frozen analog input event double-precision float point with time

.. bro:id:: dnp3_file_transport

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, file_handle: :bro:type:`count`, block_num: :bro:type:`count`, file_data: :bro:type:`string`)

   g70

.. bro:id:: dnp3_debug_byte

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, debug: :bro:type:`string`)

   Debugging event generated by the DNP3 analyzer. The "Debug_Byte" binpac unit
   generates this for unknown "cases". The user can use it to debug the byte
   string to check what caused the malformed network packets.

Bro::DNS
--------

DNS analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTS_DNS`

:bro:enum:`Analyzer::ANALYZER_DNS`

Events
++++++

.. bro:id:: dns_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`dns_msg`, len: :bro:type:`count`)

   Generated for all DNS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :is_orig:  True if the message was sent by the originator of the connection.
   

   :msg: The parsed DNS message header.
   

   :len: The length of the message's raw representation (i.e., the DNS payload).
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid  dns_query_reply dns_rejected
      dns_request non_dns_request  dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, query: :bro:type:`string`, qtype: :bro:type:`count`, qclass: :bro:type:`count`)

   Generated for DNS requests. For requests with multiple queries, this event
   is raised once for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_rejected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, query: :bro:type:`string`, qtype: :bro:type:`count`, qclass: :bro:type:`count`)

   Generated for DNS replies that reject a query. This event is raised if a DNS
   reply indicates failure because it does not pass on any
   answers to a query. Note that all of the event's parameters are parsed out of
   the reply; there's no stateful correlation with the query.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_request non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_query_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, query: :bro:type:`string`, qtype: :bro:type:`count`, qclass: :bro:type:`count`)

   Generated for each entry in the Question section of a DNS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :query: The queried name.
   

   :qtype: The queried resource record type.
   

   :qclass: The queried resource record class.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end
      dns_full_request dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_rejected
      dns_request non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_A_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, a: :bro:type:`addr`)

   Generated for DNS replies of type *A*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply
      dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_AAAA_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, a: :bro:type:`addr`)

   Generated for DNS replies of type *AAAA*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. bro:see::  dns_A_reply dns_A6_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_A6_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, a: :bro:type:`addr`)

   Generated for DNS replies of type *A6*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :a: The address returned by the reply.
   
   .. bro:see::  dns_A_reply dns_AAAA_reply dns_CNAME_reply dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_NS_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`)

   Generated for DNS replies of type *NS*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply  dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_CNAME_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply  dns_EDNS_addl dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_PTR_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`)

   Generated for DNS replies of type *PTR*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply  dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_SOA_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, soa: :bro:type:`dns_soa`)

   Generated for DNS replies of type *CNAME*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :soa: The parsed SOA value.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_WKS_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`)

   Generated for DNS replies of type *WKS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply  dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_HINFO_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`)

   Generated for DNS replies of type *HINFO*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_MX_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, name: :bro:type:`string`, preference: :bro:type:`count`)

   Generated for DNS replies of type *MX*. For replies with multiple answers, an
   individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :name: The name returned by the reply.
   

   :preference: The preference for *name* specified by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply  dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_TXT_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, strs: :bro:type:`string_vec`)

   Generated for DNS replies of type *TXT*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :strs: The textual information returned by the reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl  dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_CAA_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, flags: :bro:type:`count`, tag: :bro:type:`string`, value: :bro:type:`string`)

   Generated for DNS replies of type *CAA* (Certification Authority Authorization).
   For replies with multiple answers, an individual event of the corresponding type
   is raised for each.
   See `RFC 6844 <https://tools.ietf.org/html/rfc6844>`__ for more details.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :flags: The flags byte of the CAA reply.
   

   :tag: The property identifier of the CAA reply.
   

   :value: The property value of the CAA reply.

.. bro:id:: dns_SRV_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, target: :bro:type:`string`, priority: :bro:type:`count`, weight: :bro:type:`count`, p: :bro:type:`count`)

   Generated for DNS replies of type *SRV*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :target: Target of the SRV response -- the canonical hostname of the
           machine providing the service, ending in a dot.
   

   :priority: Priority of the SRV response -- the priority of the target
             host, lower value means more preferred.
   

   :weight: Weight of the SRV response -- a relative weight for records
           with the same priority, higher value means more preferred.
   

   :p: Port of the SRV response -- the TCP or UDP port on which the
      service is to be found.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_unknown_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`)

   Generated on DNS reply resource records when the type of record is not one
   that Bro knows how to parse and generate another more specific event.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_SRV_reply dns_end

.. bro:id:: dns_EDNS_addl

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_edns_additional`)

   Generated for DNS replies of type *EDNS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The parsed EDNS reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_HINFO_reply dns_MX_reply
      dns_NS_reply dns_PTR_reply dns_SOA_reply dns_SRV_reply dns_TSIG_addl
      dns_TXT_reply dns_WKS_reply dns_end dns_full_request dns_mapping_altered
      dns_mapping_lost_name dns_mapping_new_name dns_mapping_unverified
      dns_mapping_valid dns_message dns_query_reply dns_rejected dns_request
      non_dns_request dns_max_queries dns_session_timeout dns_skip_addl
      dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_TSIG_addl

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_tsig_additional`)

   Generated for DNS replies of type *TSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The parsed TSIG reply.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply  dns_TXT_reply dns_WKS_reply dns_end dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_RRSIG

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, rrsig: :bro:type:`dns_rrsig_rr`)

   Generated for DNS replies of type *RRSIG*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :rrsig: The parsed RRSIG record.

.. bro:id:: dns_DNSKEY

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, dnskey: :bro:type:`dns_dnskey_rr`)

   Generated for DNS replies of type *DNSKEY*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :dnskey: The parsed DNSKEY record.

.. bro:id:: dns_NSEC

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, next_name: :bro:type:`string`, bitmaps: :bro:type:`string_vec`)

   Generated for DNS replies of type *NSEC*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :next_name: The parsed next secure domain name.
   

   :bitmaps: vector of strings in hex for the bit maps present.

.. bro:id:: dns_NSEC3

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, nsec3: :bro:type:`dns_nsec3_rr`)

   Generated for DNS replies of type *NSEC3*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :nsec3: The parsed RDATA of Nsec3 record.

.. bro:id:: dns_DS

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`, ans: :bro:type:`dns_answer`, ds: :bro:type:`dns_ds_rr`)

   Generated for DNS replies of type *DS*. For replies with multiple answers,
   an individual event of the corresponding type is raised for each.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   

   :ans: The type-independent part of the parsed answer record.
   

   :ds: The parsed RDATA of DS record.

.. bro:id:: dns_end

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`dns_msg`)

   Generated at the end of processing a DNS packet. This event is the last
   ``dns_*`` event that will be raised for a DNS query/reply and signals that
   all resource records have been passed on.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Domain_Name_System>`__ for more
   information about the DNS protocol. Bro analyzes both UDP and TCP DNS
   sessions.
   

   :c: The connection, which may be UDP or TCP depending on the type of the
      transport-layer session being analyzed.
   

   :msg: The parsed DNS message header.
   
   .. bro:see:: dns_AAAA_reply dns_A_reply dns_CNAME_reply dns_EDNS_addl
      dns_HINFO_reply dns_MX_reply dns_NS_reply dns_PTR_reply dns_SOA_reply
      dns_SRV_reply dns_TSIG_addl dns_TXT_reply dns_WKS_reply dns_full_request
      dns_mapping_altered dns_mapping_lost_name dns_mapping_new_name
      dns_mapping_unverified dns_mapping_valid dns_message dns_query_reply
      dns_rejected dns_request non_dns_request dns_max_queries dns_session_timeout
      dns_skip_addl dns_skip_all_addl dns_skip_all_auth dns_skip_auth

.. bro:id:: dns_full_request

   :Type: :bro:type:`event` ()

   Deprecated. Will be removed.
   
   .. todo:: Unclear what this event is for; it's never raised. We should just
      remove it.

.. bro:id:: non_dns_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)


   :msg: The raw DNS payload.
   
   .. note:: This event is deprecated and superseded by Bro's dynamic protocol
      detection framework.

Bro::File
---------

Generic file analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_FTP_DATA`

:bro:enum:`Analyzer::ANALYZER_IRC_DATA`

Events
++++++

.. bro:id:: file_transferred

   :Type: :bro:type:`event` (c: :bro:type:`connection`, prefix: :bro:type:`string`, descr: :bro:type:`string`, mime_type: :bro:type:`string`)

   Generated when a TCP connection associated w/ file data transfer is seen
   (e.g. as happens w/ FTP or IRC).
   

   :c: The connection over which file data is transferred.
   

   :prefix: Up to 1024 bytes of the file data.
   

   :descr: Deprecated/unused argument.
   

   :mime_type: MIME type of the file or "<unknown>" if no file magic signatures
              matched.

Bro::Finger
-----------

Finger analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_FINGER`

Events
++++++

.. bro:id:: finger_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, full: :bro:type:`bool`, username: :bro:type:`string`, hostname: :bro:type:`string`)

   Generated for Finger requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :c: The connection.
   

   :full: True if verbose information is requested (``/W`` switch).
   

   :username: The request's user name.
   

   :hostname: The request's host name.
   
   .. bro:see:: finger_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: finger_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, reply_line: :bro:type:`string`)

   Generated for Finger replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Finger_protocol>`__ for more
   information about the Finger protocol.
   

   :c: The connection.
   

   :reply_line: The reply as returned by the server
   
   .. bro:see:: finger_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::FTP
--------

FTP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_FTP`

:bro:enum:`Analyzer::ANALYZER_FTP_ADAT`

Types
+++++

.. bro:type:: ftp_port

   :Type: :bro:type:`record`

      h: :bro:type:`addr`
         The host's address.

      p: :bro:type:`port`
         The host's port.

      valid: :bro:type:`bool`
         True if format was right. Only then are *h* and *p* valid.

   A parsed host/port combination describing server endpoint for an upcoming
   data transfer.
   
   .. bro:see:: fmt_ftp_port parse_eftp_port parse_ftp_epsv parse_ftp_pasv
      parse_ftp_port

Events
++++++

.. bro:id:: ftp_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, command: :bro:type:`string`, arg: :bro:type:`string`)

   Generated for client-side FTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :c: The connection.
   

   :command: The FTP command issued by the client (without any arguments).
   

   :arg: The arguments going with the command.
   
   .. bro:see:: ftp_reply fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port

.. bro:id:: ftp_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, code: :bro:type:`count`, msg: :bro:type:`string`, cont_resp: :bro:type:`bool`)

   Generated for server-side FTP replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/File_Transfer_Protocol>`__ for
   more information about the FTP protocol.
   

   :c: The connection.
   

   :code: The numerical response code the server responded with.
   

   :msg:  The textual message of the response.
   

   :cont_resp: True if the reply line is tagged as being continued to the next
              line. If so, further events will be raised and a handler may want
              to reassemble the pieces before processing the response any
              further.
   
   .. bro:see:: ftp_request fmt_ftp_port parse_eftp_port
      parse_ftp_epsv parse_ftp_pasv parse_ftp_port

Functions
+++++++++

.. bro:id:: parse_ftp_port

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts a string representation of the FTP PORT command to an
   :bro:type:`ftp_port`.
   

   :s: The string of the FTP PORT command, e.g., ``"10,0,0,1,4,31"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_eftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port

.. bro:id:: parse_eftp_port

   :Type: :bro:type:`function` (s: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts a string representation of the FTP EPRT command (see :rfc:`2428`)
   to an :bro:type:`ftp_port`.  The format is
   ``"EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :s: The string of the FTP EPRT command, e.g., ``"|1|10.0.0.1|1055|"``.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_ftp_port parse_ftp_pasv parse_ftp_epsv fmt_ftp_port

.. bro:id:: parse_ftp_pasv

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts the result of the FTP PASV command to an :bro:type:`ftp_port`.
   

   :str: The string containing the result of the FTP PASV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_ftp_port parse_eftp_port parse_ftp_epsv fmt_ftp_port

.. bro:id:: parse_ftp_epsv

   :Type: :bro:type:`function` (str: :bro:type:`string`) : :bro:type:`ftp_port`

   Converts the result of the FTP EPSV command (see :rfc:`2428`) to an
   :bro:type:`ftp_port`.  The format is ``"<text> (<d><d><d><tcp-port><d>)"``,
   where ``<d>`` is a delimiter in the ASCII range 33-126 (usually ``|``).
   

   :str: The string containing the result of the FTP EPSV command.
   

   :returns: The FTP PORT, e.g., ``[h=10.0.0.1, p=1055/tcp, valid=T]``.
   
   .. bro:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv fmt_ftp_port

.. bro:id:: fmt_ftp_port

   :Type: :bro:type:`function` (a: :bro:type:`addr`, p: :bro:type:`port`) : :bro:type:`string`

   Formats an IP address and TCP port as an FTP PORT command. For example,
   ``10.0.0.1`` and ``1055/tcp`` yields ``"10,0,0,1,4,31"``.
   

   :a: The IP address.
   

   :p: The TCP port.
   

   :returns: The FTP PORT string.
   
   .. bro:see:: parse_ftp_port parse_eftp_port parse_ftp_pasv parse_ftp_epsv

Bro::Gnutella
-------------

Gnutella analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_GNUTELLA`

Events
++++++

.. bro:id:: gnutella_text_msg

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, headers: :bro:type:`string`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see::  gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish gnutella_partial_binary_msg gnutella_signature_found
   
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_binary_msg

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, msg_type: :bro:type:`count`, ttl: :bro:type:`count`, hops: :bro:type:`count`, msg_len: :bro:type:`count`, payload: :bro:type:`string`, payload_len: :bro:type:`count`, trunc: :bro:type:`bool`, complete: :bro:type:`bool`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_establish gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_partial_binary_msg

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, msg: :bro:type:`string`, len: :bro:type:`count`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_not_establish  gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_establish

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg  gnutella_http_notify gnutella_not_establish
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_not_establish

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg gnutella_establish gnutella_http_notify
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: gnutella_http_notify

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   TODO.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Gnutella>`__ for more
   information about the Gnutella protocol.
   
   .. bro:see:: gnutella_binary_msg gnutella_establish gnutella_not_establish
      gnutella_partial_binary_msg gnutella_signature_found gnutella_text_msg
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::GSSAPI
-----------

GSSAPI analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_GSSAPI`

Events
++++++

.. bro:id:: gssapi_neg_result

   :Type: :bro:type:`event` (c: :bro:type:`connection`, state: :bro:type:`count`)

   Generated for GSSAPI negotiation results.
   

   :c: The connection.
   

   :state: The resulting state of the negotiation.
   

Bro::GTPv1
----------

GTPv1 analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_GTPV1`

Events
++++++

.. bro:id:: gtpv1_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`)

   Generated for any GTP message with a GTPv1 header.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.

.. bro:id:: gtpv1_g_pdu_packet

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner_gtp: :bro:type:`gtpv1_hdr`, inner_ip: :bro:type:`pkt_hdr`)

   Generated for GTPv1 G-PDU packets.  That is, packets with a UDP payload
   that includes a GTP header followed by an IPv4 or IPv6 packet.
   

   :outer: The GTP outer tunnel connection.
   

   :inner_gtp: The GTP header.
   

   :inner_ip: The inner IP and transport layer packet headers.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: gtpv1_create_pdp_ctx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`, elements: :bro:type:`gtp_create_pdp_ctx_request_elements`)

   Generated for GTPv1-C Create PDP Context Request messages.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.
   

   :elements: The set of Information Elements comprising the message.

.. bro:id:: gtpv1_create_pdp_ctx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`, elements: :bro:type:`gtp_create_pdp_ctx_response_elements`)

   Generated for GTPv1-C Create PDP Context Response messages.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.
   

   :elements: The set of Information Elements comprising the message.

.. bro:id:: gtpv1_update_pdp_ctx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`, elements: :bro:type:`gtp_update_pdp_ctx_request_elements`)

   Generated for GTPv1-C Update PDP Context Request messages.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.
   

   :elements: The set of Information Elements comprising the message.

.. bro:id:: gtpv1_update_pdp_ctx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`, elements: :bro:type:`gtp_update_pdp_ctx_response_elements`)

   Generated for GTPv1-C Update PDP Context Response messages.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.
   

   :elements: The set of Information Elements comprising the message.

.. bro:id:: gtpv1_delete_pdp_ctx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`, elements: :bro:type:`gtp_delete_pdp_ctx_request_elements`)

   Generated for GTPv1-C Delete PDP Context Request messages.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.
   

   :elements: The set of Information Elements comprising the message.

.. bro:id:: gtpv1_delete_pdp_ctx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`gtpv1_hdr`, elements: :bro:type:`gtp_delete_pdp_ctx_response_elements`)

   Generated for GTPv1-C Delete PDP Context Response messages.
   

   :c: The connection over which the message is sent.
   

   :hdr: The GTPv1 header.
   

   :elements: The set of Information Elements comprising the message.

Bro::HTTP
---------

HTTP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_HTTP`

Events
++++++

.. bro:id:: http_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, method: :bro:type:`string`, original_URI: :bro:type:`string`, unescaped_URI: :bro:type:`string`, version: :bro:type:`string`)

   Generated for HTTP requests. Bro supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues. This event is generated as soon as a request's initial line has
   been parsed, and before any :bro:id:`http_header` events are raised.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :method: The HTTP method extracted from the request (e.g., ``GET``, ``POST``).
   

   :original_URI: The unprocessed URI as specified in the request.
   

   :unescaped_URI: The URI with all percent-encodings decoded.
   

   :version: The version number specified in the request (e.g., ``1.1``).
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply http_stats
      truncate_http_URI http_connection_upgrade

.. bro:id:: http_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`, code: :bro:type:`count`, reason: :bro:type:`string`)

   Generated for HTTP replies. Bro supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues. This event is generated as soon as a reply's initial line has
   been parsed, and before any :bro:id:`http_header` events are raised.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :version: The version number specified in the reply (e.g., ``1.1``).
   

   :code: The numerical response code returned by the server.
   

   :reason: The textual description returned by the server along with *code*.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_request
      http_stats http_connection_upgrade

.. bro:id:: http_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, name: :bro:type:`string`, value: :bro:type:`string`)

   Generated for HTTP headers. Bro supports persistent and pipelined HTTP
   sessions and raises corresponding events as it parses client/server
   dialogues.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the header was sent by the originator of the TCP connection.
   

   :name: The name of the header.
   

   :value: The value of the header.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event  http_message_done http_reply http_request
      http_stats http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. bro:id:: http_all_headers

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, hlist: :bro:type:`mime_header_list`)

   Generated for HTTP headers, passing on all headers of an HTTP message at
   once. Bro supports persistent and pipelined HTTP sessions and raises
   corresponding events as it parses client/server dialogues.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the header was sent by the originator of the TCP connection.
   

   :hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. bro:see::  http_begin_entity http_content_type http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. bro:id:: http_begin_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated when starting to parse an HTTP body entity. This event is generated
   at least once for each non-empty (client or server) HTTP body; and
   potentially more than once if the body contains further nested MIME
   entities. Bro raises this event just before it starts parsing each entity's
   content.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the entity was sent by the originator of the TCP
            connection.
   
   .. bro:see:: http_all_headers  http_content_type http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      mime_begin_entity http_connection_upgrade

.. bro:id:: http_end_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated when finishing parsing an HTTP body entity. This event is generated
   at least once for each non-empty (client or server) HTTP body; and
   potentially more than once if the body contains further nested MIME
   entities. Bro raises this event at the point when it has finished parsing an
   entity's content.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the entity was sent by the originator of the TCP
            connection.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_entity_data
      http_event http_header http_message_done http_reply http_request
      http_stats mime_end_entity http_connection_upgrade

.. bro:id:: http_entity_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated when parsing an HTTP body entity, passing on the data. This event
   can potentially be raised many times for each entity, each time passing a
   chunk of the data of not further defined size.
   
   A common idiom for using this event is to first *reassemble* the data
   at the scripting layer by concatenating it to a successively growing
   string; and only perform further content analysis once the corresponding
   :bro:id:`http_end_entity` event has been raised. Note, however, that doing so
   can be quite expensive for HTTP tranders. At the very least, one should
   impose an upper size limit on how much data is being buffered.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :length: The length of *data*.
   

   :data: One chunk of raw entity data.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_event http_header http_message_done http_reply http_request http_stats
      mime_entity_data http_entity_data_delivery_size skip_http_data
      http_connection_upgrade

.. bro:id:: http_content_type

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, ty: :bro:type:`string`, subty: :bro:type:`string`)

   Generated for reporting an HTTP body's content type.  This event is
   generated at the end of parsing an HTTP header, passing on the MIME
   type as specified by the ``Content-Type`` header. If that header is
   missing, this event is still raised with a default value of ``text/plain``.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :ty: The main type.
   

   :subty: The subtype.
   
   .. bro:see:: http_all_headers http_begin_entity  http_end_entity http_entity_data
      http_event http_header http_message_done http_reply http_request http_stats
      http_connection_upgrade
   
   .. note:: This event is also raised for headers found in nested body
      entities.

.. bro:id:: http_message_done

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, stat: :bro:type:`http_message_stat`)

   Generated once at the end of parsing an HTTP message. Bro supports persistent
   and pipelined HTTP sessions and raises corresponding events as it parses
   client/server dialogues. A "message" is one top-level HTTP entity, such as a
   complete request or reply. Each message can have further nested sub-entities
   inside. This event is raised once all sub-entities belonging to a top-level
   message have been processed (and their corresponding ``http_entity_*`` events
   generated).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the entity was sent by the originator of the TCP
            connection.
   

   :stat: Further meta information about the message.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header  http_reply http_request http_stats
      http_connection_upgrade

.. bro:id:: http_event

   :Type: :bro:type:`event` (c: :bro:type:`connection`, event_type: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for errors found when decoding HTTP requests or replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol>`__
   for more information about the HTTP protocol.
   

   :c: The connection.
   

   :event_type: A string describing the general category of the problem found
               (e.g., ``illegal format``).
   

   :detail: Further more detailed description of the error.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data  http_header http_message_done http_reply http_request
      http_stats mime_event http_connection_upgrade

.. bro:id:: http_stats

   :Type: :bro:type:`event` (c: :bro:type:`connection`, stats: :bro:type:`http_stats_rec`)

   Generated at the end of an HTTP session to report statistics about it. This
   event is raised after all of an HTTP session's requests and replies have been
   fully processed.
   

   :c: The connection.
   

   :stats: Statistics summarizing HTTP-level properties of the finished
          connection.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply
      http_request http_connection_upgrade

.. bro:id:: http_connection_upgrade

   :Type: :bro:type:`event` (c: :bro:type:`connection`, protocol: :bro:type:`string`)

   Generated when a HTTP session is upgraded to a different protocol (e.g. websocket).
   This event is raised when a server replies with a HTTP 101 reply. No more HTTP events
   will be raised after this event.
   

   :c: The connection.
   

   :protocol: The protocol to which the connection is switching.
   
   .. bro:see:: http_all_headers http_begin_entity http_content_type http_end_entity
      http_entity_data http_event http_header http_message_done http_reply
      http_request

Functions
+++++++++

.. bro:id:: skip_http_entity_data

   :Type: :bro:type:`function` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`) : :bro:type:`any`

   Skips the data of the HTTP entity.
   

   :c: The HTTP connection.
   

   :is_orig: If true, the client data is skipped, and the server data otherwise.
   
   .. bro:see:: skip_smtp_data

.. bro:id:: unescape_URI

   :Type: :bro:type:`function` (URI: :bro:type:`string`) : :bro:type:`string`

   Unescapes all characters in a URI (decode every ``%xx`` group).
   

   :URI: The URI to unescape.
   

   :returns: The unescaped URI with all ``%xx`` groups decoded.
   
   .. note::
   
        Unescaping reserved characters may cause loss of information.
        :rfc:`2396`: A URI is always in an "escaped" form, since escaping or
        unescaping a completed URI might change its semantics.  Normally, the
        only time escape encodings can safely be made is when the URI is
        being created from its component parts.

Bro::ICMP
---------

ICMP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_ICMP`

Events
++++++

.. bro:id:: icmp_sent

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`)

   Generated for all ICMP messages that are not handled separately with
   dedicated ICMP events. Bro's ICMP analyzer handles a number of ICMP messages
   directly with dedicated events. This event acts as a fallback for those it
   doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   
   .. bro:see:: icmp_error_message icmp_sent_payload

.. bro:id:: icmp_sent_payload

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, payload: :bro:type:`string`)

   The same as :bro:see:`icmp_sent` except containing the ICMP payload.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :payload: The payload of the ICMP message.
   
   .. bro:see:: icmp_error_message icmp_sent_payload

.. bro:id:: icmp_echo_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, id: :bro:type:`count`, seq: :bro:type:`count`, payload: :bro:type:`string`)

   Generated for ICMP *echo request* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :id: The *echo request* identifier.
   

   :seq: The *echo request* sequence number.
   

   :payload: The message-specific data of the packet payload, i.e., everything
            after the first 8 bytes of the ICMP header.
   
   .. bro:see:: icmp_echo_reply

.. bro:id:: icmp_echo_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, id: :bro:type:`count`, seq: :bro:type:`count`, payload: :bro:type:`string`)

   Generated for ICMP *echo reply* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :id: The *echo reply* identifier.
   

   :seq: The *echo reply* sequence number.
   

   :payload: The message-specific data of the packet payload, i.e., everything
            after the first 8 bytes of the ICMP header.
   
   .. bro:see:: icmp_echo_request

.. bro:id:: icmp_error_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

   Generated for all ICMPv6 error messages that are not handled
   separately with dedicated events. Bro's ICMP analyzer handles a number
   of ICMP error messages directly with dedicated events. This event acts
   as a fallback for those it doesn't.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard
         connection record *c*.
   

   :code: The ICMP code of the error message.
   

   :context: A record with specifics of the original packet that the message
            refers to.
   
   .. bro:see:: icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem

.. bro:id:: icmp_unreachable

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

   Generated for ICMP *destination unreachable* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *unreachable* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Unreachable* messages should include the original IP
            header from the packet that triggered them, and Bro parses that
            into the *context* structure. Note that if the *unreachable*
            includes only a partial IP header for some reason, no
            fields of *context* will be filled out.
   
   .. bro:see:: icmp_error_message icmp_packet_too_big
      icmp_time_exceeded icmp_parameter_problem

.. bro:id:: icmp_packet_too_big

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

   Generated for ICMPv6 *packet too big* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *too big* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Too big* messages should include the original IP header
            from the packet that triggered them, and Bro parses that into
            the *context* structure. Note that if the *too big* includes only
            a partial IP header for some reason, no fields of *context* will
            be filled out.
   
   .. bro:see:: icmp_error_message icmp_unreachable
      icmp_time_exceeded icmp_parameter_problem

.. bro:id:: icmp_time_exceeded

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

   Generated for ICMP *time exceeded* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *exceeded* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Unreachable* messages should include the original IP
            header from the packet that triggered them, and Bro parses that
            into the *context* structure. Note that if the *exceeded* includes
            only a partial IP header for some reason, no fields of *context*
            will be filled out.
   
   .. bro:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_parameter_problem

.. bro:id:: icmp_parameter_problem

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, code: :bro:type:`count`, context: :bro:type:`icmp_context`)

   Generated for ICMPv6 *parameter problem* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/ICMPv6>`__ for more
   information about the ICMPv6 protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :code: The ICMP code of the *parameter problem* message.
   

   :context: A record with specifics of the original packet that the message
            refers to. *Parameter problem* messages should include the original
            IP header from the packet that triggered them, and Bro parses that
            into the *context* structure. Note that if the *parameter problem*
            includes only a partial IP header for some reason, no fields
            of *context* will be filled out.
   
   .. bro:see:: icmp_error_message icmp_unreachable icmp_packet_too_big
      icmp_time_exceeded

.. bro:id:: icmp_router_solicitation

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *router solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. bro:id:: icmp_router_advertisement

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, cur_hop_limit: :bro:type:`count`, managed: :bro:type:`bool`, other: :bro:type:`bool`, home_agent: :bro:type:`bool`, pref: :bro:type:`count`, proxy: :bro:type:`bool`, rsv: :bro:type:`count`, router_lifetime: :bro:type:`interval`, reachable_time: :bro:type:`interval`, retrans_timer: :bro:type:`interval`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *router advertisement* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :cur_hop_limit: The default value that should be placed in Hop Count field
                  for outgoing IP packets.
   

   :managed: Managed address configuration flag, :rfc:`4861`.
   

   :other: Other stateful configuration flag, :rfc:`4861`.
   

   :home_agent: Mobile IPv6 home agent flag, :rfc:`3775`.
   

   :pref: Router selection preferences, :rfc:`4191`.
   

   :proxy: Neighbor discovery proxy flag, :rfc:`4389`.
   

   :rsv: Remaining two reserved bits of router advertisement flags.
   

   :router_lifetime: How long this router should be used as a default router.
   

   :reachable_time: How long a neighbor should be considered reachable.
   

   :retrans_timer: How long a host should wait before retransmitting.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_solicitation
      icmp_neighbor_solicitation icmp_neighbor_advertisement icmp_redirect

.. bro:id:: icmp_neighbor_solicitation

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, tgt: :bro:type:`addr`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor solicitation* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :tgt: The IP address of the target of the solicitation.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_advertisement icmp_redirect

.. bro:id:: icmp_neighbor_advertisement

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, router: :bro:type:`bool`, solicited: :bro:type:`bool`, override: :bro:type:`bool`, tgt: :bro:type:`addr`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *neighbor advertisement* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :router: Flag indicating the sender is a router.
   

   :solicited: Flag indicating advertisement is in response to a solicitation.
   

   :override: Flag indicating advertisement should override existing caches.
   

   :tgt: the Target Address in the soliciting message or the address whose
        link-layer address has changed for unsolicited adverts.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_redirect

.. bro:id:: icmp_redirect

   :Type: :bro:type:`event` (c: :bro:type:`connection`, icmp: :bro:type:`icmp_conn`, tgt: :bro:type:`addr`, dest: :bro:type:`addr`, options: :bro:type:`icmp6_nd_options`)

   Generated for ICMP *redirect* messages.
   
   See `Wikipedia
   <http://en.wikipedia.org/wiki/Internet_Control_Message_Protocol>`__ for more
   information about the ICMP protocol.
   

   :c: The connection record for the corresponding ICMP flow.
   

   :icmp: Additional ICMP-specific information augmenting the standard connection
         record *c*.
   

   :tgt: The address that is supposed to be a better first hop to use for
        ICMP Destination Address.
   

   :dest: The address of the destination which is redirected to the target.
   

   :options: Any Neighbor Discovery options included with message (:rfc:`4861`).
   
   .. bro:see:: icmp_router_solicitation icmp_router_advertisement
      icmp_neighbor_solicitation icmp_neighbor_advertisement

Bro::Ident
----------

Ident analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_IDENT`

Events
++++++

.. bro:id:: ident_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, lport: :bro:type:`port`, rport: :bro:type:`port`)

   Generated for Ident requests.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The request's local port.
   

   :rport: The request's remote port.
   
   .. bro:see:: ident_error ident_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: ident_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, lport: :bro:type:`port`, rport: :bro:type:`port`, user_id: :bro:type:`string`, system: :bro:type:`string`)

   Generated for Ident replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The corresponding request's local port.
   

   :rport: The corresponding request's remote port.
   

   :user_id: The user id returned by the reply.
   

   :system: The operating system returned by the reply.
   
   .. bro:see:: ident_error  ident_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: ident_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, lport: :bro:type:`port`, rport: :bro:type:`port`, line: :bro:type:`string`)

   Generated for Ident error replies.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ident_protocol>`__ for more
   information about the Ident protocol.
   

   :c: The connection.
   

   :lport: The corresponding request's local port.
   

   :rport: The corresponding request's remote port.
   

   :line: The error description returned by the reply.
   
   .. bro:see:: ident_reply ident_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::IMAP
---------

IMAP analyzer (StartTLS only)

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_IMAP`

Events
++++++

.. bro:id:: imap_capabilities

   :Type: :bro:type:`event` (c: :bro:type:`connection`, capabilities: :bro:type:`string_vec`)

   Generated when a server sends a capability list to the client,
   after being queried using the CAPABILITY command.
   

   :c: The connection.
   

   :capabilities: The list of IMAP capabilities as sent by the server.

.. bro:id:: imap_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a IMAP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :c: The connection.

Bro::InterConn
--------------

InterConn analyzer deprecated

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_INTERCONN`

Events
++++++

.. bro:id:: interconn_stats

   :Type: :bro:type:`event` (c: :bro:type:`connection`, os: :bro:type:`interconn_endp_stats`, rs: :bro:type:`interconn_endp_stats`)

   Deprecated. Will be removed.

.. bro:id:: interconn_remove_conn

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Deprecated. Will be removed.

Bro::IRC
--------

IRC analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_IRC`

Events
++++++

.. bro:id:: irc_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, command: :bro:type:`string`, arguments: :bro:type:`string`)

   Generated for all client-side IRC commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: Always true.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :command: The command.
   

   :arguments: The arguments for the command.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message
   
   .. note:: This event is generated only for messages that originate
      at the client-side. Commands coming in from remote trigger
      the :bro:id:`irc_message` event instead.

.. bro:id:: irc_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, code: :bro:type:`count`, params: :bro:type:`string`)

   Generated for all IRC replies. IRC replies are sent in response to a
   request and come with a reply code.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the reply. IRC uses the prefix to
           indicate the true origin of a message.
   

   :code: The reply code, as specified by the protocol.
   

   :params: The reply's parameters.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, command: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC commands forwarded from the server to the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :command: The command.
   

   :message: TODO.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message  irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message
   
   .. note::
   
      This event is generated only for messages that are forwarded by the server
      to the client. Commands coming from client trigger the
      :bro:id:`irc_request` event instead.

.. bro:id:: irc_quit_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *quit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname coming with the message.
   

   :message: The text included with the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_privmsg_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, source: :bro:type:`string`, target: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *privmsg*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :source: The source of the private communication.
   

   :target: The target of the private communication.
   

   :message: The text of communication.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_notice_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, source: :bro:type:`string`, target: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *notice*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :source: The source of the private communication.
   

   :target: The target of the private communication.
   

   :message: The text of communication.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message  irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_squery_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, source: :bro:type:`string`, target: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *squery*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :source: The source of the private communication.
   

   :target: The target of the private communication.
   

   :message: The text of communication.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_join_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, info_list: :bro:type:`irc_join_list`)

   Generated for IRC messages of type *join*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :info_list: The user information coming with the command.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_part_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, chans: :bro:type:`string_set`, message: :bro:type:`string`)

   Generated for IRC messages of type *part*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname coming with the message.
   

   :chans: The set of channels affected.
   

   :message: The text coming with the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_password_message

.. bro:id:: irc_nick_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, who: :bro:type:`string`, newnick: :bro:type:`string`)

   Generated for IRC messages of type *nick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :who: The user changing its nickname.
   

   :newnick: The new nickname.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_invalid_nick

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated when a server rejects an IRC nickname.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users  irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_network_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, users: :bro:type:`count`, services: :bro:type:`count`, servers: :bro:type:`count`)

   Generated for an IRC reply of type *luserclient*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :users: The number of users as returned in the reply.
   

   :services: The number of services as returned in the reply.
   

   :servers: The number of servers as returned in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_server_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, users: :bro:type:`count`, services: :bro:type:`count`, servers: :bro:type:`count`)

   Generated for an IRC reply of type *luserme*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :users: The number of users as returned in the reply.
   

   :services: The number of services as returned in the reply.
   

   :servers: The number of servers as returned in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_channel_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, chans: :bro:type:`count`)

   Generated for an IRC reply of type *luserchannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :chans: The number of channels as returned in the reply.
   
   .. bro:see::  irc_channel_topic irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_who_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, target_nick: :bro:type:`string`, channel: :bro:type:`string`, user: :bro:type:`string`, host: :bro:type:`string`, server: :bro:type:`string`, nick: :bro:type:`string`, params: :bro:type:`string`, hops: :bro:type:`count`, real_name: :bro:type:`string`)

   Generated for an IRC reply of type *whoreply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :target_nick: The target nickname.
   

   :channel: The channel.
   

   :user: The user.
   

   :host: The host.
   

   :server: The server.
   

   :nick: The nickname.
   

   :params: The parameters.
   

   :hops: The hop count.
   

   :real_name: The real name.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_names_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, c_type: :bro:type:`string`, channel: :bro:type:`string`, users: :bro:type:`string_set`)

   Generated for an IRC reply of type *namereply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :c_type: The channel type.
   

   :channel: The channel.
   

   :users: The set of users.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message  irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_whois_operator_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`)

   Generated for an IRC reply of type *whoisoperator*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_channel_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, chans: :bro:type:`string_set`)

   Generated for an IRC reply of type *whoischannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   

   :chans: The set of channels returned.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_user_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, user: :bro:type:`string`, host: :bro:type:`string`, real_name: :bro:type:`string`)

   Generated for an IRC reply of type *whoisuser*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   

   :user: The user name specified in the reply.
   

   :host: The host name specified in the reply.
   

   :real_name: The real name specified in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_oper_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, got_oper: :bro:type:`bool`)

   Generated for IRC replies of type *youreoper* and *nooperhost*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :got_oper: True if the *oper* command was executed successfully
             (*youreport*) and false otherwise (*nooperhost*).
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_part_message
      irc_password_message

.. bro:id:: irc_global_users

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, msg: :bro:type:`string`)

   Generated for an IRC reply of type *globalusers*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :msg: The message coming with the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_channel_topic

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, channel: :bro:type:`string`, topic: :bro:type:`string`)

   Generated for an IRC reply of type *topic*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :channel: The channel name specified in the reply.
   

   :topic: The topic specified in the reply.
   
   .. bro:see:: irc_channel_info  irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_who_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, mask: :bro:type:`string`, oper: :bro:type:`bool`)

   Generated for IRC messages of type *who*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :mask: The mask specified in the message.
   

   :oper: True if the operator flag was set.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, server: :bro:type:`string`, users: :bro:type:`string`)

   Generated for IRC messages of type *whois*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :server: TODO.
   

   :users: TODO.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_oper_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated for IRC messages of type *oper*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :user: The user specified in the message.
   

   :password: The password specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message  irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_kick_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, chans: :bro:type:`string`, users: :bro:type:`string`, comment: :bro:type:`string`)

   Generated for IRC messages of type *kick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :chans: The channels specified in the message.
   

   :users: The users specified in the message.
   

   :comment: The comment specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_error_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *error*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :message: The textual description specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_invite_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, nickname: :bro:type:`string`, channel: :bro:type:`string`)

   Generated for IRC messages of type *invite*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :nickname: The nickname specified in the message.
   

   :channel: The channel specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick  irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_mode_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, params: :bro:type:`string`)

   Generated for IRC messages of type *mode*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :params: The parameters coming with the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message  irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_squit_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, server: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *squit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :server: The server specified in the message.
   

   :message: The textual description specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_dcc_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, target: :bro:type:`string`, dcc_type: :bro:type:`string`, argument: :bro:type:`string`, address: :bro:type:`addr`, dest_port: :bro:type:`count`, size: :bro:type:`count`)

   Generated for IRC messages of type *dcc*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :target: The target specified in the message.
   

   :dcc_type: The DCC type specified in the message.
   

   :argument:  The argument specified in the message.
   

   :address: The address specified in the message.
   

   :dest_port: The destination port specified in the message.
   

   :size: The size specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic  irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_user_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, host: :bro:type:`string`, server: :bro:type:`string`, real_name: :bro:type:`string`)

   Generated for IRC messages of type *user*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :user: The user specified in the message.
   

   :host: The host name specified in the message.
   

   :server: The server name specified in the message.
   

   :real_name: The real name specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_password_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, password: :bro:type:`string`)

   Generated for IRC messages of type *password*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :password: The password specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message

.. bro:id:: irc_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated if an IRC connection switched to TLS using STARTTLS. After this
   event no more IRC events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :c: The connection.

Bro::KRB
--------

Kerberos analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_KRB`

:bro:enum:`Analyzer::ANALYZER_KRB_TCP`

Options/Constants
+++++++++++++++++

.. bro:id:: KRB::keytab

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``""``

   Kerberos keytab file name. Used to decrypt tickets encountered on the wire.

Types
+++++

.. bro:type:: KRB::Error_Msg

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (30 for ERROR_MSG)

      client_time: :bro:type:`time` :bro:attr:`&optional`
         Current time on the client

      server_time: :bro:type:`time`
         Current time on the server

      error_code: :bro:type:`count`
         The specific error code

      client_realm: :bro:type:`string` :bro:attr:`&optional`
         Realm of the ticket

      client_name: :bro:type:`string` :bro:attr:`&optional`
         Name on the ticket

      service_realm: :bro:type:`string`
         Realm of the service

      service_name: :bro:type:`string`
         Name of the service

      error_text: :bro:type:`string` :bro:attr:`&optional`
         Additional text to explain the error

      pa_data: :bro:type:`vector` of :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Optional pre-authentication data

   The data from the ERROR_MSG message. See :rfc:`4120`.

.. bro:type:: KRB::SAFE_Msg

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (20 for SAFE_MSG)

      data: :bro:type:`string`
         The application-specific data that is being passed
         from the sender to the reciever

      timestamp: :bro:type:`time` :bro:attr:`&optional`
         Current time from the sender of the message

      seq: :bro:type:`count` :bro:attr:`&optional`
         Sequence number used to detect replays

      sender: :bro:type:`KRB::Host_Address` :bro:attr:`&optional`
         Sender address

      recipient: :bro:type:`KRB::Host_Address` :bro:attr:`&optional`
         Recipient address

   The data from the SAFE message. See :rfc:`4120`.

.. bro:type:: KRB::KDC_Options

   :Type: :bro:type:`record`

      forwardable: :bro:type:`bool`
         The ticket to be issued should have its forwardable flag set.

      forwarded: :bro:type:`bool`
         A (TGT) request for forwarding.

      proxiable: :bro:type:`bool`
         The ticket to be issued should have its proxiable flag set.

      proxy: :bro:type:`bool`
         A request for a proxy.

      allow_postdate: :bro:type:`bool`
         The ticket to be issued should have its may-postdate flag set.

      postdated: :bro:type:`bool`
         A request for a postdated ticket.

      renewable: :bro:type:`bool`
         The ticket to be issued should have its renewable  flag set.

      opt_hardware_auth: :bro:type:`bool`
         Reserved for opt_hardware_auth

      disable_transited_check: :bro:type:`bool`
         Request that the KDC not check the transited field of a TGT against
         the policy of the local realm before it will issue derivative tickets
         based on the TGT.

      renewable_ok: :bro:type:`bool`
         If a ticket with the requested lifetime cannot be issued, a renewable
         ticket is acceptable

      enc_tkt_in_skey: :bro:type:`bool`
         The ticket for the end server is to be encrypted in the session key
         from the additional TGT provided

      renew: :bro:type:`bool`
         The request is for a renewal

      validate: :bro:type:`bool`
         The request is to validate a postdated ticket.

   KDC Options. See :rfc:`4120`

.. bro:type:: KRB::AP_Options

   :Type: :bro:type:`record`

      use_session_key: :bro:type:`bool`
         Indicates that user-to-user-authentication is in use

      mutual_required: :bro:type:`bool`
         Mutual authentication is required

   AP Options. See :rfc:`4120`

.. bro:type:: KRB::Type_Value

   :Type: :bro:type:`record`

      data_type: :bro:type:`count`
         The data type

      val: :bro:type:`string`
         The data value

   Used in a few places in the Kerberos analyzer for elements
   that have a type and a string value.

.. bro:type:: KRB::Ticket

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      realm: :bro:type:`string`
         Realm

      service_name: :bro:type:`string`
         Name of the service

      cipher: :bro:type:`count`
         Cipher the ticket was encrypted with

      ciphertext: :bro:type:`string` :bro:attr:`&optional`
         Cipher text of the ticket

      authenticationinfo: :bro:type:`string` :bro:attr:`&optional`
         Authentication info

   A Kerberos ticket. See :rfc:`4120`.

.. bro:type:: KRB::Ticket_Vector

   :Type: :bro:type:`vector` of :bro:type:`KRB::Ticket`


.. bro:type:: KRB::Host_Address

   :Type: :bro:type:`record`

      ip: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         IPv4 or IPv6 address

      netbios: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         NetBIOS address

      unknown: :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Some other type that we don't support yet

   A Kerberos host address See :rfc:`4120`.

.. bro:type:: KRB::KDC_Request

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (10 for AS_REQ, 12 for TGS_REQ)

      pa_data: :bro:type:`vector` of :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Optional pre-authentication data

      kdc_options: :bro:type:`KRB::KDC_Options`
         Options specified in the request

      client_name: :bro:type:`string` :bro:attr:`&optional`
         Name on the ticket

      service_realm: :bro:type:`string`
         Realm of the service

      service_name: :bro:type:`string` :bro:attr:`&optional`
         Name of the service

      from: :bro:type:`time` :bro:attr:`&optional`
         Time the ticket is good from

      till: :bro:type:`time`
         Time the ticket is good till

      rtime: :bro:type:`time` :bro:attr:`&optional`
         The requested renew-till time

      nonce: :bro:type:`count`
         A random nonce generated by the client

      encryption_types: :bro:type:`vector` of :bro:type:`count`
         The desired encryption algorithms, in order of preference

      host_addrs: :bro:type:`vector` of :bro:type:`KRB::Host_Address` :bro:attr:`&optional`
         Any additional addresses the ticket should be valid for

      additional_tickets: :bro:type:`vector` of :bro:type:`KRB::Ticket` :bro:attr:`&optional`
         Additional tickets may be included for certain transactions

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

.. bro:type:: KRB::KDC_Response

   :Type: :bro:type:`record`

      pvno: :bro:type:`count`
         Protocol version number (5 for KRB5)

      msg_type: :bro:type:`count`
         The message type (11 for AS_REP, 13 for TGS_REP)

      pa_data: :bro:type:`vector` of :bro:type:`KRB::Type_Value` :bro:attr:`&optional`
         Optional pre-authentication data

      client_realm: :bro:type:`string` :bro:attr:`&optional`
         Realm on the ticket

      client_name: :bro:type:`string`
         Name on the service

      ticket: :bro:type:`KRB::Ticket`
         The ticket that was issued

   The data from the AS_REQ and TGS_REQ messages. See :rfc:`4120`.

Events
++++++

.. bro:id:: krb_as_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Authentication Server (AS) Request`` as defined
   in :rfc:`4120`. The AS request contains a username of the client
   requesting authentication, and returns an AS reply with an
   encrypted Ticket Granting Ticket (TGT) for that user. The TGT
   can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC request message data structure.
   
   .. bro:see:: krb_as_response krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_as_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Authentication Server (AS) Response`` as defined
   in :rfc:`4120`. Following the AS request for a user, an AS reply
   contains an encrypted Ticket Granting Ticket (TGT) for that user.
   The TGT can then be used to request further tickets for other services.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC reply message data structure.
   
   .. bro:see:: krb_as_request krb_tgs_request krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_tgs_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Request`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Request`` as defined
   in :rfc:`4120`. Following the Authentication Server exchange, if
   successful, the client now has a Ticket Granting Ticket (TGT). To
   authenticate to a Kerberized service, the client requests a Service
   Ticket, which will be returned in the TGS reply.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC request message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_response krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_tgs_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::KDC_Response`)

   A Kerberos 5 ``Ticket Granting Service (TGS) Response`` as defined
   in :rfc:`4120`. This message returns a Service Ticket to the client,
   which is encrypted with the service's long-term key, and which the
   client can use to authenticate to that service.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos KDC reply message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_ap_request
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_ap_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, ticket: :bro:type:`KRB::Ticket`, opts: :bro:type:`KRB::AP_Options`)

   A Kerberos 5 ``Authentication Header (AP) Request`` as defined
   in :rfc:`4120`. This message contains authentication information
   that should be part of the first message in an authenticated
   transaction.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :ticket: The Kerberos ticket being used for authentication.
   

   :opts: A Kerberos AP options data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_response krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_ap_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   A Kerberos 5 ``Authentication Header (AP) Response`` as defined
   in :rfc:`4120`. This is used if mutual authentication is desired.
   All of the interesting information in here is encrypted, so the event
   doesn't have much useful data, but it's provided in case it's important
   to know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_priv krb_safe krb_cred krb_error

.. bro:id:: krb_priv

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   A Kerberos 5 ``Private Message`` as defined in :rfc:`4120`. This
   is a private (encrypted) application message, so the event doesn't
   have much useful data, but it's provided in case it's important to
   know that this message was sent.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :is_orig: Whether the originator of the connection sent this message.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_safe krb_cred krb_error

.. bro:id:: krb_safe

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`KRB::SAFE_Msg`)

   A Kerberos 5 ``Safe Message`` as defined in :rfc:`4120`. This is a
   safe (checksummed) application message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :is_orig: Whether the originator of the connection sent this message.
   

   :msg: A Kerberos SAFE message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_cred krb_error

.. bro:id:: krb_cred

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, tickets: :bro:type:`KRB::Ticket_Vector`)

   A Kerberos 5 ``Credential Message`` as defined in :rfc:`4120`. This is
   a private (encrypted) message to forward credentials.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :is_orig: Whether the originator of the connection sent this message.
   

   :tickets: Tickets obtained from the KDC that are being forwarded.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_error

.. bro:id:: krb_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`KRB::Error_Msg`)

   A Kerberos 5 ``Error Message`` as defined in :rfc:`4120`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Kerberos_%28protocol%29>`__ for
   more information about the Kerberos protocol.
   

   :c: The connection over which this Kerberos message was sent.
   

   :msg: A Kerberos error message data structure.
   
   .. bro:see:: krb_as_request krb_as_response krb_tgs_request krb_tgs_response
      krb_ap_request krb_ap_response krb_priv krb_safe krb_cred

Bro::Login
----------

Telnet/Rsh/Rlogin analyzers

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTS_RLOGIN`

:bro:enum:`Analyzer::ANALYZER_CONTENTS_RSH`

:bro:enum:`Analyzer::ANALYZER_LOGIN`

:bro:enum:`Analyzer::ANALYZER_NVT`

:bro:enum:`Analyzer::ANALYZER_RLOGIN`

:bro:enum:`Analyzer::ANALYZER_RSH`

:bro:enum:`Analyzer::ANALYZER_TELNET`

Events
++++++

.. bro:id:: rsh_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, client_user: :bro:type:`string`, server_user: :bro:type:`string`, line: :bro:type:`string`, new_session: :bro:type:`bool`)

   Generated for client side commands on an RSH connection.
   
   See :rfc:`1258` for more information about the Rlogin/Rsh protocol.
   

   :c: The connection.
   

   :client_user: The client-side user name as sent in the initial protocol
         handshake.
   

   :server_user: The server-side user name as sent in the initial protocol
         handshake.
   

   :line: The command line sent in the request.
   

   :new_session: True if this is the first command of the Rsh session.
   
   .. bro:see:: rsh_reply login_confused login_confused_text login_display
      login_failure login_input_line login_output_line login_prompt login_success
      login_terminal
   
   .. note:: For historical reasons, these events are separate from the
      ``login_`` events. Ideally, they would all be handled uniquely.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: rsh_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, client_user: :bro:type:`string`, server_user: :bro:type:`string`, line: :bro:type:`string`)

   Generated for client side commands on an RSH connection.
   
   See :rfc:`1258` for more information about the Rlogin/Rsh protocol.
   

   :c: The connection.
   

   :client_user: The client-side user name as sent in the initial protocol
         handshake.
   

   :server_user: The server-side user name as sent in the initial protocol
         handshake.
   

   :line: The command line sent in the request.
   
   .. bro:see:: rsh_request login_confused login_confused_text login_display
      login_failure login_input_line login_output_line login_prompt login_success
      login_terminal
   
   .. note:: For historical reasons, these events are separate from the
      ``login_`` events. Ideally, they would all be handled uniquely.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: login_failure

   :Type: :bro:type:`event` (c: :bro:type:`connection`, user: :bro:type:`string`, client_user: :bro:type:`string`, password: :bro:type:`string`, line: :bro:type:`string`)

   Generated for Telnet/Rlogin login failures. The *login* analyzer inspects
   Telnet/Rlogin sessions to heuristically extract username and password
   information as well as the text returned by the login server. This event is
   raised if a login attempt appears to have been unsuccessful.
   

   :c: The connection.
   

   :user: The user name tried.
   

   :client_user: For Telnet connections, this is an empty string, but for Rlogin
         connections, it is the client name passed in the initial authentication
         information (to check against .rhosts).
   

   :password:  The password tried.
   

   :line:  The line of text that led the analyzer to conclude that the
          authentication had failed.
   
   .. bro:see:: login_confused login_confused_text login_display login_input_line
      login_output_line login_prompt login_success login_terminal direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts login_success_msgs
      login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying login attempts. This
      configuration has not yet been ported over from Bro 1.5 to Bro 2.x, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_success

   :Type: :bro:type:`event` (c: :bro:type:`connection`, user: :bro:type:`string`, client_user: :bro:type:`string`, password: :bro:type:`string`, line: :bro:type:`string`)

   Generated for successful Telnet/Rlogin logins. The *login* analyzer inspects
   Telnet/Rlogin sessions to heuristically extract username and password
   information as well as the text returned by the login server. This event is
   raised if a login attempt appears to have been successful.
   

   :c: The connection.
   

   :user: The user name used.
   

   :client_user: For Telnet connections, this is an empty string, but for Rlogin
         connections, it is the client name passed in the initial authentication
         information (to check against .rhosts).
   

   :password: The password used.
   

   :line:  The line of text that led the analyzer to conclude that the
          authentication had succeeded.
   
   .. bro:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line login_prompt login_terminal
      direct_login_prompts get_login_state login_failure_msgs login_non_failure_msgs
      login_prompts login_success_msgs login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying login attempts. This
      configuration has not yet been ported over from Bro 1.5 to Bro 2.x, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_input_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, line: :bro:type:`string`)

   Generated for lines of input on Telnet/Rlogin sessions. The line will have
   control characters (such as in-band Telnet options) removed.
   

   :c: The connection.
   

   :line: The input line.
   
   .. bro:see:: login_confused login_confused_text login_display login_failure
      login_output_line login_prompt login_success login_terminal    rsh_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_output_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, line: :bro:type:`string`)

   Generated for lines of output on Telnet/Rlogin sessions. The line will have
   control characters (such as in-band Telnet options) removed.
   

   :c: The connection.
   

   :line: The ouput line.
   
   .. bro:see:: login_confused login_confused_text login_display login_failure
      login_input_line  login_prompt login_success login_terminal rsh_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_confused

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`, line: :bro:type:`string`)

   Generated when tracking of Telnet/Rlogin authentication failed. As Bro's
   *login* analyzer uses a number of heuristics to extract authentication
   information, it may become confused. If it can no longer correctly track
   the authentication dialog, it raises this event.
   

   :c: The connection.
   

   :msg: Gives the particular problem the heuristics detected (for example,
        ``multiple_login_prompts`` means that the engine saw several login
        prompts in a row, without the type-ahead from the client side presumed
        necessary to cause them)
   

   :line: The line of text that caused the heuristics to conclude they were
         confused.
   
   .. bro:see::  login_confused_text login_display login_failure login_input_line login_output_line
      login_prompt login_success login_terminal direct_login_prompts get_login_state
      login_failure_msgs login_non_failure_msgs login_prompts login_success_msgs
      login_timeouts set_login_state
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_confused_text

   :Type: :bro:type:`event` (c: :bro:type:`connection`, line: :bro:type:`string`)

   Generated after getting confused while tracking a Telnet/Rlogin
   authentication dialog. The *login* analyzer generates this even for every
   line of user input after it has reported :bro:id:`login_confused` for a
   connection.
   

   :c: The connection.
   

   :line: The line the user typed.
   
   .. bro:see:: login_confused  login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts
      login_success_msgs login_timeouts set_login_state
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_terminal

   :Type: :bro:type:`event` (c: :bro:type:`connection`, terminal: :bro:type:`string`)

   Generated for clients transmitting a terminal type in a Telnet session.  This
   information is extracted out of environment variables sent as Telnet options.
   

   :c: The connection.
   

   :terminal: The TERM value transmitted.
   
   .. bro:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line login_prompt login_success
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_display

   :Type: :bro:type:`event` (c: :bro:type:`connection`, display: :bro:type:`string`)

   Generated for clients transmitting an X11 DISPLAY in a Telnet session. This
   information is extracted out of environment variables sent as Telnet options.
   

   :c: The connection.
   

   :display: The DISPLAY transmitted.
   
   .. bro:see:: login_confused login_confused_text  login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: authentication_accepted

   :Type: :bro:type:`event` (name: :bro:type:`string`, c: :bro:type:`connection`)

   Generated when a Telnet authentication has been successful. The Telnet
   protocol includes options for negotiating authentication. When such an
   option is sent from client to server and the server replies that it accepts
   the authentication, then the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :name: The authenticated name.
   

   :c: The connection.
   
   .. bro:see::  authentication_rejected authentication_skipped login_success
   
   .. note::  This event inspects the corresponding Telnet option
      while :bro:id:`login_success` heuristically determines success by watching
      session data.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: authentication_rejected

   :Type: :bro:type:`event` (name: :bro:type:`string`, c: :bro:type:`connection`)

   Generated when a Telnet authentication has been unsuccessful. The Telnet
   protocol includes options for negotiating authentication. When such an option
   is sent from client to server and the server replies that it did not accept
   the authentication, then the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :name: The attempted authentication name.
   

   :c: The connection.
   
   .. bro:see:: authentication_accepted authentication_skipped login_failure
   
   .. note::  This event inspects the corresponding Telnet option
      while :bro:id:`login_success` heuristically determines failure by watching
      session data.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: authentication_skipped

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for Telnet/Rlogin sessions when a pattern match indicates
   that no authentication is performed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :c: The connection.
   
   .. bro:see:: authentication_accepted authentication_rejected direct_login_prompts
      get_login_state login_failure_msgs login_non_failure_msgs login_prompts
      login_success_msgs login_timeouts set_login_state
   
   .. note:: The login analyzer depends on a set of script-level variables that
      need to be configured with patterns identifying activity. This
      configuration has not yet been ported over from Bro 1.5 to Bro 2.x, and
      the analyzer is therefore not directly usable at the moment.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: login_prompt

   :Type: :bro:type:`event` (c: :bro:type:`connection`, prompt: :bro:type:`string`)

   Generated for clients transmitting a terminal prompt in a Telnet session.
   This information is extracted out of environment variables sent as Telnet
   options.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :c: The connection.
   

   :prompt: The TTYPROMPT transmitted.
   
   .. bro:see:: login_confused login_confused_text login_display login_failure
      login_input_line login_output_line  login_success login_terminal
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: activating_encryption

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for Telnet sessions when encryption is activated. The Telnet
   protocol includes options for negotiating encryption. When such a series of
   options is successfully negotiated, the event engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :c: The connection.
   
   .. bro:see:: authentication_accepted authentication_rejected authentication_skipped
      login_confused login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal

.. bro:id:: inconsistent_option

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for an inconsistent Telnet option. Telnet options are specified
   by the client and server stating which options they are willing to
   support vs. which they are not, and then instructing one another which in
   fact they should or should not use for the current connection. If the event
   engine sees a peer violate either what the other peer has instructed it to
   do, or what it itself offered in terms of options in the past, then the
   engine generates this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :c: The connection.
   
   .. bro:see:: bad_option bad_option_termination  authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal

.. bro:id:: bad_option

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for an ill-formed or unrecognized Telnet option.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :c: The connection.
   
   .. bro:see:: inconsistent_option bad_option_termination authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: bad_option_termination

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for a Telnet option that's incorrectly terminated.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Telnet>`__ for more information
   about the Telnet protocol.
   

   :c: The connection.
   
   .. bro:see:: inconsistent_option bad_option authentication_accepted
      authentication_rejected authentication_skipped login_confused
      login_confused_text login_display login_failure login_input_line
      login_output_line login_prompt login_success login_terminal
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

Functions
+++++++++

.. bro:id:: get_login_state

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`) : :bro:type:`count`

   Returns the state of the given login (Telnet or Rlogin) connection.
   

   :cid: The connection ID.
   

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
   
   .. bro:see:: set_login_state

.. bro:id:: set_login_state

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, new_state: :bro:type:`count`) : :bro:type:`bool`

   Sets the login state of a connection with a login analyzer.
   

   :cid: The connection ID.
   

   :new_state: The new state of the login analyzer. See
              :bro:id:`get_login_state` for possible values.
   

   :returns: Returns false if *cid* is not an active connection
            or is not tagged as a login analyzer, and true otherwise.
   
   .. bro:see:: get_login_state

Bro::MIME
---------

MIME parsing

Components
++++++++++

Events
++++++

.. bro:id:: mime_begin_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when starting to parse an email MIME entity. MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Bro raises this event when it
   begins parsing a MIME entity extracted from an email protocol.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   
   .. bro:see:: mime_all_data mime_all_headers  mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_begin_entity
   
   .. note:: Bro also extracts MIME entities from HTTP sessions. For those,
      however, it raises :bro:id:`http_begin_entity` instead.

.. bro:id:: mime_end_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when finishing parsing an email MIME entity.  MIME is a
   protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. Bro raises this event when it
   finished parsing a MIME entity extracted from an email protocol.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_entity_data mime_event mime_one_header mime_segment_data smtp_data
      http_end_entity
   
   .. note:: Bro also extracts MIME entities from HTTP sessions. For those,
      however, it raises :bro:id:`http_end_entity` instead.

.. bro:id:: mime_one_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, h: :bro:type:`mime_header_rec`)

   Generated for individual MIME headers extracted from email MIME
   entities.  MIME is a protocol-independent data format for encoding text and
   files, along with corresponding metadata, for transmission.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :h: The parsed MIME header.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event  mime_segment_data
      http_header  http_all_headers
   
   .. note:: Bro also extracts MIME headers from HTTP sessions. For those,
      however, it raises :bro:id:`http_header` instead.

.. bro:id:: mime_all_headers

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hlist: :bro:type:`mime_header_list`)

   Generated for MIME headers extracted from email MIME entities, passing all
   headers at once.  MIME is a protocol-independent data format for encoding
   text and files, along with corresponding metadata, for transmission.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :hlist: A *table* containing all headers extracted from the current entity.
          The table is indexed by the position of the header (1 for the first,
          2 for the second, etc.).
   
   .. bro:see:: mime_all_data  mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
      http_header  http_all_headers
   
   .. note:: Bro also extracts MIME headers from HTTP sessions. For those,
      however, it raises :bro:id:`http_header` instead.

.. bro:id:: mime_segment_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated for chunks of decoded MIME data from email MIME entities.  MIME
   is a protocol-independent data format for encoding text and files, along with
   corresponding metadata, for transmission. As Bro parses the data of an
   entity, it raises a sequence of these events, each coming as soon as a new
   chunk of data is available. In contrast, there is also
   :bro:id:`mime_entity_data`, which passes all of an entities data at once
   in a single block. While the latter is more convenient to handle,
   ``mime_segment_data`` is more efficient as Bro does not need to buffer
   the data. Thus, if possible, this event should be preferred.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :length: The length of *data*.
   

   :data: The raw data of one segment of the current entity.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header http_entity_data
      mime_segment_length mime_segment_overlap_length
   
   .. note:: Bro also extracts MIME data from HTTP sessions. For those,
      however, it raises :bro:id:`http_entity_data` (sic!) instead.

.. bro:id:: mime_entity_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated for data decoded from an email MIME entity. This event delivers
   the complete content of a single MIME entity with the quoted-printable and
   and base64 data decoded. In contrast, there is also :bro:id:`mime_segment_data`,
   which passes on a sequence of data chunks as they come in. While
   ``mime_entity_data`` is more convenient to handle, ``mime_segment_data`` is
   more efficient as Bro does not need to buffer the data. Thus, if possible,
   the latter should be preferred.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :length: The length of *data*.
   

   :data: The raw data of the complete entity.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity  mime_event mime_one_header mime_segment_data
   
   .. note:: While Bro also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. bro:id:: mime_all_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, length: :bro:type:`count`, data: :bro:type:`string`)

   Generated for passing on all data decoded from a single email MIME
   message. If an email message has more than one MIME entity, this event
   combines all their data into a single value for analysis. Note that because
   of the potentially significant buffering necessary, using this event can be
   expensive.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :length: The length of *data*.
   

   :data: The raw data of all MIME entities concatenated.
   
   .. bro:see::  mime_all_headers mime_begin_entity mime_content_hash mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Bro also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

.. bro:id:: mime_event

   :Type: :bro:type:`event` (c: :bro:type:`connection`, event_type: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for errors found when decoding email MIME entities.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :event_type: A string describing the general category of the problem found
      (e.g., ``illegal format``).
   

   :detail: Further more detailed description of the error.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data  mime_one_header mime_segment_data http_event
   
   .. note:: Bro also extracts MIME headers from HTTP sessions. For those,
      however, it raises :bro:id:`http_event` instead.

.. bro:id:: mime_content_hash

   :Type: :bro:type:`event` (c: :bro:type:`connection`, content_len: :bro:type:`count`, hash_value: :bro:type:`string`)

   Generated for decoded MIME entities extracted from email messages, passing on
   their MD5 checksums. Bro computes the MD5 over the complete decoded data of
   each MIME entity.
   
   Bro's MIME analyzer for emails currently supports SMTP and POP3. See
   `Wikipedia <http://en.wikipedia.org/wiki/MIME>`__ for more information
   about MIME.
   

   :c: The connection.
   

   :content_len: The length of the entity being hashed.
   

   :hash_value: The MD5 hash.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_end_entity
      mime_entity_data mime_event mime_one_header mime_segment_data
   
   .. note:: While Bro also decodes MIME entities extracted from HTTP
      sessions, there's no corresponding event for that currently.

Bro::Modbus
-----------

Modbus analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_MODBUS`

Events
++++++

.. bro:id:: modbus_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, is_orig: :bro:type:`bool`)

   Generated for any Modbus message regardless if the particular function
   is further supported or not.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :is_orig: True if the event is raised for the originator side.

.. bro:id:: modbus_exception

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, code: :bro:type:`count`)

   Generated for any Modbus exception message.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :code: The exception code.

.. bro:id:: modbus_read_coils_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read coils request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be read.
   

   :quantity: The number of coils to be read.

.. bro:id:: modbus_read_coils_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, coils: :bro:type:`ModbusCoils`)

   Generated for a Modbus read coils response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :coils: The coil values returned from the device.

.. bro:id:: modbus_read_discrete_inputs_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read discrete inputs request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be read.
   

   :quantity: The number of coils to be read.

.. bro:id:: modbus_read_discrete_inputs_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, coils: :bro:type:`ModbusCoils`)

   Generated for a Modbus read discrete inputs response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :coils: The coil values returned from the device.

.. bro:id:: modbus_read_holding_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read holding registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be read.
   

   :quantity: The number of registers to be read.

.. bro:id:: modbus_read_holding_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read holding registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :registers: The register values returned from the device.

.. bro:id:: modbus_read_input_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus read input registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be read.
   

   :quantity: The number of registers to be read.

.. bro:id:: modbus_read_input_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read input registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :registers: The register values returned from the device.

.. bro:id:: modbus_write_single_coil_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`bool`)

   Generated for a Modbus write single coil request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the coil to be written.
   

   :value: The value to be written to the coil.

.. bro:id:: modbus_write_single_coil_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`bool`)

   Generated for a Modbus write single coil response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the coil that was written.
   

   :value: The value that was written to the coil.

.. bro:id:: modbus_write_single_register_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`count`)

   Generated for a Modbus write single register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register to be written.
   

   :value: The value to be written to the register.

.. bro:id:: modbus_write_single_register_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, value: :bro:type:`count`)

   Generated for a Modbus write single register response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register that was written.
   

   :value: The value that was written to the register.

.. bro:id:: modbus_write_multiple_coils_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, coils: :bro:type:`ModbusCoils`)

   Generated for a Modbus write multiple coils request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil to be written.
   

   :coils: The values to be written to the coils.

.. bro:id:: modbus_write_multiple_coils_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus write multiple coils response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first coil that was written.
   

   :quantity: The quantity of coils that were written.

.. bro:id:: modbus_write_multiple_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus write multiple registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register to be written.
   

   :registers: The values to be written to the registers.

.. bro:id:: modbus_write_multiple_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`, quantity: :bro:type:`count`)

   Generated for a Modbus write multiple registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The memory address of the first register that was written.
   

   :quantity: The quantity of registers that were written.

.. bro:id:: modbus_read_file_record_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus read file record request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_read_file_record_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus read file record response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_write_file_record_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus write file record request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_write_file_record_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`)

   Generated for a Modbus write file record response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   
   .. note: This event is incomplete.  The information from the data structure
            is not yet passed through to the event.

.. bro:id:: modbus_mask_write_register_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, and_mask: :bro:type:`count`, or_mask: :bro:type:`count`)

   Generated for a Modbus mask write register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register where the masks should be applied.
   

   :and_mask: The value of the logical AND mask to apply to the register.
   

   :or_mask: The value of the logical OR mask to apply to the register.

.. bro:id:: modbus_mask_write_register_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, address: :bro:type:`count`, and_mask: :bro:type:`count`, or_mask: :bro:type:`count`)

   Generated for a Modbus mask write register request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :address: The memory address of the register where the masks were applied.
   

   :and_mask: The value of the logical AND mask applied register.
   

   :or_mask: The value of the logical OR mask applied to the register.

.. bro:id:: modbus_read_write_multiple_registers_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, read_start_address: :bro:type:`count`, read_quantity: :bro:type:`count`, write_start_address: :bro:type:`count`, write_registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :read_start_address: The memory address of the first register to be read.
   

   :read_quantity: The number of registers to read.
   

   :write_start_address: The memory address of the first register to be written.
   

   :write_registers: The values to be written to the registers.

.. bro:id:: modbus_read_write_multiple_registers_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, written_registers: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read/write multiple registers response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :written_registers: The register values read from the registers specified in
                      the request.

.. bro:id:: modbus_read_fifo_queue_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, start_address: :bro:type:`count`)

   Generated for a Modbus read FIFO queue request.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :start_address: The address of the FIFO queue to read.

.. bro:id:: modbus_read_fifo_queue_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, headers: :bro:type:`ModbusHeaders`, fifos: :bro:type:`ModbusRegisters`)

   Generated for a Modbus read FIFO queue response.
   

   :c: The connection.
   

   :headers: The headers for the modbus function.
   

   :fifos: The register values read from the FIFO queue on the device.

Bro::MySQL
----------

MySQL analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_MYSQL`

Events
++++++

.. bro:id:: mysql_command_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, command: :bro:type:`count`, arg: :bro:type:`string`)

   Generated for a command request from a MySQL client.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :command: The numerical code of the command issued.
   

   :arg: The argument for the command (empty string if not provided).
   
   .. bro:see:: mysql_error mysql_ok mysql_server_version mysql_handshake

.. bro:id:: mysql_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, code: :bro:type:`count`, msg: :bro:type:`string`)

   Generated for an unsuccessful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :code: The error code.
   

   :msg: Any extra details about the error (empty string if not provided).
   
   .. bro:see:: mysql_command_request mysql_ok mysql_server_version mysql_handshake

.. bro:id:: mysql_ok

   :Type: :bro:type:`event` (c: :bro:type:`connection`, affected_rows: :bro:type:`count`)

   Generated for a successful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :affected_rows: The number of rows that were affected.
   
   .. bro:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. bro:id:: mysql_result_row

   :Type: :bro:type:`event` (c: :bro:type:`connection`, row: :bro:type:`string_vec`)

   Generated for each MySQL ResultsetRow response packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :row: The result row data.
   
   .. bro:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake mysql_ok

.. bro:id:: mysql_server_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, ver: :bro:type:`string`)

   Generated for the initial server handshake packet, which includes the MySQL server version.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :ver: The server version string.
   
   .. bro:see:: mysql_command_request mysql_error mysql_ok mysql_handshake

.. bro:id:: mysql_handshake

   :Type: :bro:type:`event` (c: :bro:type:`connection`, username: :bro:type:`string`)

   Generated for a client handshake response packet, which includes the username the client is attempting
   to connect as.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :username: The username supplied by the client
   
   .. bro:see:: mysql_command_request mysql_error mysql_ok mysql_server_version

Bro::NCP
--------

NCP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTS_NCP`

:bro:enum:`Analyzer::ANALYZER_NCP`

Options/Constants
+++++++++++++++++

.. bro:id:: NCP::max_frame_size

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``65536``

   The maximum number of bytes to allocate when parsing NCP frames.

Events
++++++

.. bro:id:: ncp_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, frame_type: :bro:type:`count`, length: :bro:type:`count`, func: :bro:type:`count`)

   Generated for NCP requests (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :c: The connection.
   

   :frame_type: The frame type, as specified by the protocol.
   

   :length: The length of the request body, excluding the frame header.
   

   :func: The requested function, as specified by the protocol.
   
   .. bro:see:: ncp_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: ncp_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, frame_type: :bro:type:`count`, length: :bro:type:`count`, req_frame: :bro:type:`count`, req_func: :bro:type:`count`, completion_code: :bro:type:`count`)

   Generated for NCP replies (Netware Core Protocol).
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetWare_Core_Protocol>`__ for
   more information about the NCP protocol.
   

   :c: The connection.
   

   :frame_type: The frame type, as specified by the protocol.
   

   :length: The length of the request body, excluding the frame header.
   

   :req_frame: The frame type from the corresponding request.
   

   :req_func: The function code from the corresponding request.
   

   :completion_code: The reply's completion code, as specified by the protocol.
   
   .. bro:see:: ncp_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::NetBIOS
------------

NetBIOS analyzer support

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTS_NETBIOSSSN`

:bro:enum:`Analyzer::ANALYZER_NETBIOSSSN`

Events
++++++

.. bro:id:: netbios_session_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg_type: :bro:type:`count`, data_len: :bro:type:`count`)

   Generated for all NetBIOS SSN and DGM messages. Bro's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :is_orig:  True if the message was sent by the originator of the connection.
   

   :msg_type: The general type of message, as defined in Section 4.3.1 of
             :rfc:`1002`.
   

   :data_len: The length of the message's payload.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp  decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *session request*. Bro's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_accepted

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *positive session response*. Bro's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see::  netbios_session_keepalive netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_rejected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *negative session response*. Bro's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_raw_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *session message* that are not
   carrying an SMB payload.
   
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :is_orig: True if the message was sent by the originator of the connection.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header (i.e., the ``user_data``).
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event. In fact, it's probably an odd event
      to have to begin with.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_ret_arg_resp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *retarget response*. Bro's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_request decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_keepalive

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *keep-alive*. Bro's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Functions
+++++++++

.. bro:id:: decode_netbios_name

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`string`

   Decode a NetBIOS name.  See http://support.microsoft.com/kb/194203.
   

   :name: The encoded NetBIOS name, e.g., ``"FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF"``.
   

   :returns: The decoded NetBIOS name, e.g., ``"THE NETBIOS NAME"``.
   
   .. bro:see:: decode_netbios_name_type

.. bro:id:: decode_netbios_name_type

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`count`

   Converts a NetBIOS name type to its corresponding numeric value.
   See http://support.microsoft.com/kb/163409.
   

   :name: The NetBIOS name type.
   

   :returns: The numeric value of *name*.
   
   .. bro:see:: decode_netbios_name

Bro::NTLM
---------

NTLM analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_NTLM`

Types
+++++

.. bro:type:: NTLM::Negotiate

   :Type: :bro:type:`record`

      flags: :bro:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The domain name of the client, if known

      workstation: :bro:type:`string` :bro:attr:`&optional`
         The machine name of the client, if known

      version: :bro:type:`NTLM::Version` :bro:attr:`&optional`
         The Windows version information, if supplied


.. bro:type:: NTLM::Challenge

   :Type: :bro:type:`record`

      flags: :bro:type:`NTLM::NegotiateFlags`
         The negotiate flags

      target_name: :bro:type:`string` :bro:attr:`&optional`
         The server authentication realm. If the server is
         domain-joined, the name of the domain. Otherwise
         the server name. See flags.target_type_domain
         and flags.target_type_server

      version: :bro:type:`NTLM::Version` :bro:attr:`&optional`
         The Windows version information, if supplied

      target_info: :bro:type:`NTLM::AVs` :bro:attr:`&optional`
         Attribute-value pairs specified by the server


.. bro:type:: NTLM::Authenticate

   :Type: :bro:type:`record`

      flags: :bro:type:`NTLM::NegotiateFlags`
         The negotiate flags

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The domain or computer name hosting the account

      user_name: :bro:type:`string` :bro:attr:`&optional`
         The name of the user to be authenticated.

      workstation: :bro:type:`string` :bro:attr:`&optional`
         The name of the computer to which the user was logged on.

      session_key: :bro:type:`string` :bro:attr:`&optional`
         The session key

      version: :bro:type:`NTLM::Version` :bro:attr:`&optional`
         The Windows version information, if supplied


.. bro:type:: NTLM::NegotiateFlags

   :Type: :bro:type:`record`

      negotiate_56: :bro:type:`bool`
         If set, requires 56-bit encryption

      negotiate_key_exch: :bro:type:`bool`
         If set, requests an explicit key exchange

      negotiate_128: :bro:type:`bool`
         If set, requests 128-bit session key negotiation

      negotiate_version: :bro:type:`bool`
         If set, requests the protocol version number

      negotiate_target_info: :bro:type:`bool`
         If set, indicates that the TargetInfo fields in the
         CHALLENGE_MESSAGE are populated

      request_non_nt_session_key: :bro:type:`bool`
         If set, requests the usage of the LMOWF function

      negotiate_identify: :bro:type:`bool`
         If set, requests and identify level token

      negotiate_extended_sessionsecurity: :bro:type:`bool`
         If set, requests usage of NTLM v2 session security
         Note: NTML v2 session security is actually NTLM v1

      target_type_server: :bro:type:`bool`
         If set, TargetName must be a server name

      target_type_domain: :bro:type:`bool`
         If set, TargetName must be a domain name

      negotiate_always_sign: :bro:type:`bool`
         If set, requests the presence of a signature block
         on all messages

      negotiate_oem_workstation_supplied: :bro:type:`bool`
         If set, the workstation name is provided

      negotiate_oem_domain_supplied: :bro:type:`bool`
         If set, the domain name is provided

      negotiate_anonymous_connection: :bro:type:`bool`
         If set, the connection should be anonymous

      negotiate_ntlm: :bro:type:`bool`
         If set, requests usage of NTLM v1

      negotiate_lm_key: :bro:type:`bool`
         If set, requests LAN Manager session key computation

      negotiate_datagram: :bro:type:`bool`
         If set, requests connectionless authentication

      negotiate_seal: :bro:type:`bool`
         If set, requests session key negotiation for message 
         confidentiality

      negotiate_sign: :bro:type:`bool`
         If set, requests session key negotiation for message
         signatures

      request_target: :bro:type:`bool`
         If set, the TargetName field is present

      negotiate_oem: :bro:type:`bool`
         If set, requests OEM character set encoding

      negotiate_unicode: :bro:type:`bool`
         If set, requests Unicode character set encoding


.. bro:type:: NTLM::Version

   :Type: :bro:type:`record`

      major: :bro:type:`count`
         The major version of the Windows operating system in use

      minor: :bro:type:`count`
         The minor version of the Windows operating system in use

      build: :bro:type:`count`
         The build number of the Windows operating system in use

      ntlmssp: :bro:type:`count`
         The current revision of NTLMSSP in use


.. bro:type:: NTLM::AVs

   :Type: :bro:type:`record`

      nb_computer_name: :bro:type:`string`
         The server's NetBIOS computer name

      nb_domain_name: :bro:type:`string`
         The server's NetBIOS domain name

      dns_computer_name: :bro:type:`string` :bro:attr:`&optional`
         The FQDN of the computer

      dns_domain_name: :bro:type:`string` :bro:attr:`&optional`
         The FQDN of the domain

      dns_tree_name: :bro:type:`string` :bro:attr:`&optional`
         The FQDN of the forest

      constrained_auth: :bro:type:`bool` :bro:attr:`&optional`
         Indicates to the client that the account
         authentication is constrained

      timestamp: :bro:type:`time` :bro:attr:`&optional`
         The associated timestamp, if present

      single_host_id: :bro:type:`count` :bro:attr:`&optional`
         Indicates that the client is providing
         a machine ID created at computer startup to
         identify the calling machine

      target_name: :bro:type:`string` :bro:attr:`&optional`
         The SPN of the target server


Events
++++++

.. bro:id:: ntlm_negotiate

   :Type: :bro:type:`event` (c: :bro:type:`connection`, negotiate: :bro:type:`NTLM::Negotiate`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *negotiate*.
   

   :c: The connection.
   

   :negotiate: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. bro:see:: ntlm_challenge ntlm_authenticate

.. bro:id:: ntlm_challenge

   :Type: :bro:type:`event` (c: :bro:type:`connection`, challenge: :bro:type:`NTLM::Challenge`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *challenge*.
   

   :c: The connection.
   

   :negotiate: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. bro:see:: ntlm_negotiate ntlm_authenticate

.. bro:id:: ntlm_authenticate

   :Type: :bro:type:`event` (c: :bro:type:`connection`, request: :bro:type:`NTLM::Authenticate`)

   Generated for :abbr:`NTLM (NT LAN Manager)` messages of type *authenticate*.
   

   :c: The connection.
   

   :request: The parsed data of the :abbr:`NTLM (NT LAN Manager)` message. See init-bare for more details.
   
   .. bro:see:: ntlm_negotiate ntlm_challenge

Bro::NTP
--------

NTP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_NTP`

Events
++++++

.. bro:id:: ntp_message

   :Type: :bro:type:`event` (u: :bro:type:`connection`, msg: :bro:type:`ntp_msg`, excess: :bro:type:`string`)

   Generated for all NTP messages. Different from many other of Bro's events,
   this one is generated for both client-side and server-side messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Network_Time_Protocol>`__ for
   more information about the NTP protocol.
   

   :u: The connection record describing the corresponding UDP flow.
   

   :msg: The parsed NTP message.
   

   :excess: The raw bytes of any optional parts of the NTP packet. Bro does not
           further parse any optional fields.
   
   .. bro:see:: ntp_session_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::PIA
--------

Analyzers implementing Dynamic Protocol

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_PIA_TCP`

:bro:enum:`Analyzer::ANALYZER_PIA_UDP`

Bro::POP3
---------

POP3 analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_POP3`

Events
++++++

.. bro:id:: pop3_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, command: :bro:type:`string`, arg: :bro:type:`string`)

   Generated for client-side commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :command: The command sent.
   

   :arg: The argument to the command.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, cmd: :bro:type:`string`, msg: :bro:type:`string`)

   Generated for server-side replies to commands on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :cmd: The success indicator sent by the server. This corresponds to the
        first token on the line sent, and should be either ``OK`` or ``ERR``.
   

   :msg: The textual description the server sent along with *cmd*.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_request
      pop3_unexpected
   
   .. todo:: This event is receiving odd parameters, should unify.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data: :bro:type:`string`)

   Generated for server-side multi-line responses on POP3 connections. POP3
   connections use multi-line responses to send bulk data, such as the actual
   mails. This event is generated once for each line that's part of such a
   response.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the data was sent by the originator of the TCP connection.
   

   :data: The data sent.
   
   .. bro:see:: pop3_login_failure pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_unexpected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for errors encountered on POP3 sessions. If the POP3 analyzer
   finds state transitions that do not conform to the protocol specification,
   or other situations it can't handle, it raises this event.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: True if the data was sent by the originator of the TCP connection.
   

   :msg: A textual description of the situation.
   

   :detail: The input that triggered the event.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply pop3_request
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a POP3 connection goes encrypted. While POP3 is by default a
   clear-text protocol, extensions exist to switch to encryption. This event is
   generated if that happens and the analyzer then stops processing the
   connection.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_login_success pop3_reply
      pop3_request pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_login_success

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated for successful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :user: The user name used for authentication. The event is only generated if
         a non-empty user name was used.
   

   :password: The password used for authentication.
   
   .. bro:see:: pop3_data pop3_login_failure pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pop3_login_failure

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated for unsuccessful authentications on POP3 connections.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/POP3>`__ for more information
   about the POP3 protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :user: The user name attempted for authentication. The event is only
         generated if a non-empty user name was used.
   

   :password: The password attempted for authentication.
   
   .. bro:see:: pop3_data pop3_login_success pop3_reply pop3_request
      pop3_unexpected
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::RADIUS
-----------

RADIUS analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_RADIUS`

Types
+++++

.. bro:type:: RADIUS::AttributeList

   :Type: :bro:type:`vector` of :bro:type:`string`


.. bro:type:: RADIUS::Attributes

   :Type: :bro:type:`table` [:bro:type:`count`] of :bro:type:`RADIUS::AttributeList`


.. bro:type:: RADIUS::Message

   :Type: :bro:type:`record`

      code: :bro:type:`count`
         The type of message (Access-Request, Access-Accept, etc.).

      trans_id: :bro:type:`count`
         The transaction ID.

      authenticator: :bro:type:`string`
         The "authenticator" string.

      attributes: :bro:type:`RADIUS::Attributes` :bro:attr:`&optional`
         Any attributes.


Events
++++++

.. bro:id:: radius_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`RADIUS::Message`)

   Generated for RADIUS messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :c: The connection.
   

   :result: A record containing fields parsed from a RADIUS packet.
   

.. bro:id:: radius_attribute

   :Type: :bro:type:`event` (c: :bro:type:`connection`, attr_type: :bro:type:`count`, value: :bro:type:`string`)

   Generated for each RADIUS attribute.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/RADIUS>`__ for more
   information about RADIUS.
   

   :c: The connection.
   

   :attr_type: The value of the code field (1 == User-Name, 2 == User-Password, etc.).
   

   :value: The data/value bound to the attribute.
   

Bro::RDP
--------

RDP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_RDP`

Types
+++++

.. bro:type:: RDP::EarlyCapabilityFlags

   :Type: :bro:type:`record`

      support_err_info_pdu: :bro:type:`bool`

      want_32bpp_session: :bro:type:`bool`

      support_statusinfo_pdu: :bro:type:`bool`

      strong_asymmetric_keys: :bro:type:`bool`

      support_monitor_layout_pdu: :bro:type:`bool`

      support_netchar_autodetect: :bro:type:`bool`

      support_dynvc_gfx_protocol: :bro:type:`bool`

      support_dynamic_time_zone: :bro:type:`bool`

      support_heartbeat_pdu: :bro:type:`bool`


.. bro:type:: RDP::ClientCoreData

   :Type: :bro:type:`record`

      version_major: :bro:type:`count`

      version_minor: :bro:type:`count`

      desktop_width: :bro:type:`count`

      desktop_height: :bro:type:`count`

      color_depth: :bro:type:`count`

      sas_sequence: :bro:type:`count`

      keyboard_layout: :bro:type:`count`

      client_build: :bro:type:`count`

      client_name: :bro:type:`string`

      keyboard_type: :bro:type:`count`

      keyboard_sub: :bro:type:`count`

      keyboard_function_key: :bro:type:`count`

      ime_file_name: :bro:type:`string`

      post_beta2_color_depth: :bro:type:`count` :bro:attr:`&optional`

      client_product_id: :bro:type:`string` :bro:attr:`&optional`

      serial_number: :bro:type:`count` :bro:attr:`&optional`

      high_color_depth: :bro:type:`count` :bro:attr:`&optional`

      supported_color_depths: :bro:type:`count` :bro:attr:`&optional`

      ec_flags: :bro:type:`RDP::EarlyCapabilityFlags` :bro:attr:`&optional`

      dig_product_id: :bro:type:`string` :bro:attr:`&optional`


Events
++++++

.. bro:id:: rdp_connect_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, cookie: :bro:type:`string`)

   Generated for X.224 client requests.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :cookie: The cookie included in the request.

.. bro:id:: rdp_negotiation_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, security_protocol: :bro:type:`count`)

   Generated for RDP Negotiation Response messages.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :security_protocol: The security protocol selected by the server.

.. bro:id:: rdp_negotiation_failure

   :Type: :bro:type:`event` (c: :bro:type:`connection`, failure_code: :bro:type:`count`)

   Generated for RDP Negotiation Failure messages.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :failure_code: The failure code sent by the server.

.. bro:id:: rdp_client_core_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, data: :bro:type:`RDP::ClientCoreData`)

   Generated for MCS client requests.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :data: The data contained in the client core data structure.

.. bro:id:: rdp_gcc_server_create_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`count`)

   Generated for MCS server responses.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :result: The 8-bit integer representing the GCC Conference Create Response result.

.. bro:id:: rdp_server_security

   :Type: :bro:type:`event` (c: :bro:type:`connection`, encryption_method: :bro:type:`count`, encryption_level: :bro:type:`count`)

   Generated for MCS server responses.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :encryption_method: The 32-bit integer representing the encryption method used in the connection.
   

   :encryption_level: The 32-bit integer representing the encryption level used in the connection.

.. bro:id:: rdp_server_certificate

   :Type: :bro:type:`event` (c: :bro:type:`connection`, cert_type: :bro:type:`count`, permanently_issued: :bro:type:`bool`)

   Generated for a server certificate section.  If multiple X.509 
   certificates are included in chain, this event will still
   only be generated a single time.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :cert_type: Indicates the type of certificate.
   

   :permanently_issued: Value will be true is the certificate(s) is permanent on the server.

.. bro:id:: rdp_begin_encryption

   :Type: :bro:type:`event` (c: :bro:type:`connection`, security_protocol: :bro:type:`count`)

   Generated when an RDP session becomes encrypted.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :security_protocol: The security protocol being used for the session.

Bro::RFB
--------

Parser for rfb (VNC) analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_RFB`

Events
++++++

.. bro:id:: rfb_event

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for RFB event
   

   :c: The connection record for the underlying transport-layer session/flow.

.. bro:id:: rfb_authentication_type

   :Type: :bro:type:`event` (c: :bro:type:`connection`, authtype: :bro:type:`count`)

   Generated for RFB event authentication mechanism selection
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :authtype: the value of the chosen authentication mechanism

.. bro:id:: rfb_auth_result

   :Type: :bro:type:`event` (c: :bro:type:`connection`, result: :bro:type:`bool`)

   Generated for RFB event authentication result message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :result: whether or not authentication was succesful

.. bro:id:: rfb_share_flag

   :Type: :bro:type:`event` (c: :bro:type:`connection`, flag: :bro:type:`bool`)

   Generated for RFB event share flag messages
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :flag: whether or not the share flag was set

.. bro:id:: rfb_client_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, major_version: :bro:type:`string`, minor_version: :bro:type:`string`)

   Generated for RFB event client banner message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :version: of the client's rfb library

.. bro:id:: rfb_server_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, major_version: :bro:type:`string`, minor_version: :bro:type:`string`)

   Generated for RFB event server banner message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :version: of the server's rfb library

.. bro:id:: rfb_server_parameters

   :Type: :bro:type:`event` (c: :bro:type:`connection`, name: :bro:type:`string`, width: :bro:type:`count`, height: :bro:type:`count`)

   Generated for RFB event server parameter message
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :name: name of the shared screen
   

   :width: width of the shared screen
   

   :height: height of the shared screen

Bro::RPC
--------

Analyzers for RPC-based protocols

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTS_NFS`

:bro:enum:`Analyzer::ANALYZER_CONTENTS_RPC`

:bro:enum:`Analyzer::ANALYZER_MOUNT`

:bro:enum:`Analyzer::ANALYZER_NFS`

:bro:enum:`Analyzer::ANALYZER_PORTMAPPER`

Events
++++++

.. bro:id:: nfs_proc_null

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`)

   Generated for NFSv3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented  nfs_proc_read nfs_proc_readdir nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_getattr

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, fh: :bro:type:`string`, attrs: :bro:type:`NFS3::fattr_t`)

   Generated for NFSv3 request/reply dialogues of type *getattr*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :fh: TODO.
   

   :attrs: The attributes returned in the reply. The values may not be valid if
         the request was unsuccessful.
   
   .. bro:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_sattr

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::sattrargs_t`, rep: :bro:type:`NFS3::sattr_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *sattr*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The attributes returned in the reply. The values may not be
        valid if the request was unsuccessful.
   
   .. bro:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_lookup

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::lookup_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *lookup*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr  nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_read

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::readargs_t`, rep: :bro:type:`NFS3::read_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *read*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_remove nfs_proc_rmdir
      nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
      NFS3::return_data NFS3::return_data_first_only NFS3::return_data_max
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_readlink

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, fh: :bro:type:`string`, rep: :bro:type:`NFS3::readlink_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *readlink*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :fh: The file handle passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_symlink rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_symlink

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::symlinkargs_t`, rep: :bro:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *symlink*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The attributes returned in the reply. The values may not be
        valid if the request was unsuccessful.
   
   .. bro:see:: nfs_proc_create  nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      nfs_proc_link rpc_call rpc_dialogue rpc_reply file_mode
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_link

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::linkargs_t`, rep: :bro:type:`NFS3::link_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *link*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      nfs_proc_symlink rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_write

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::writeargs_t`, rep: :bro:type:`NFS3::write_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *write*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir  nfs_reply_status rpc_call
      rpc_dialogue rpc_reply NFS3::return_data NFS3::return_data_first_only
      NFS3::return_data_max
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_create

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *create*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see::  nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_mkdir

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::newobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *mkdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status
      rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_remove

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::delobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *remove*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink  nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_rmdir

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::diropargs_t`, rep: :bro:type:`NFS3::delobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *rmdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove  nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_rename

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::renameopargs_t`, rep: :bro:type:`NFS3::renameobj_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *rename*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rename nfs_proc_write
      nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_readdir

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, req: :bro:type:`NFS3::readdirargs_t`, rep: :bro:type:`NFS3::readdir_reply_t`)

   Generated for NFSv3 request/reply dialogues of type *readdir*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req: TODO.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readlink
      nfs_proc_remove nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_proc_not_implemented

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`, proc: :bro:type:`NFS3::proc_t`)

   Generated for NFSv3 request/reply dialogues of a type that Bro's NFSv3
   analyzer does not implement.
   
   NFS is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Network_File_System_(protocol)>`__ for more
   information about the service.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :proc: The procedure called that Bro does not implement.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_null nfs_proc_read nfs_proc_readdir nfs_proc_readlink nfs_proc_remove
      nfs_proc_rmdir nfs_proc_write nfs_reply_status rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: nfs_reply_status

   :Type: :bro:type:`event` (n: :bro:type:`connection`, info: :bro:type:`NFS3::info_t`)

   Generated for each NFSv3 reply message received, reporting just the
   status included.
   

   :n: The connection.
   

   :info: Reports the status included in the reply.
   
   .. bro:see:: nfs_proc_create nfs_proc_getattr nfs_proc_lookup nfs_proc_mkdir
      nfs_proc_not_implemented nfs_proc_null nfs_proc_read nfs_proc_readdir
      nfs_proc_readlink nfs_proc_remove nfs_proc_rmdir nfs_proc_write rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_null

   :Type: :bro:type:`event` (r: :bro:type:`connection`)

   Generated for Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   
   .. bro:see:: pm_request_set pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_set

   :Type: :bro:type:`event` (r: :bro:type:`connection`, m: :bro:type:`pm_mapping`, success: :bro:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The argument to the request.
   

   :success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. bro:see:: pm_request_null pm_request_unset pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_unset

   :Type: :bro:type:`event` (r: :bro:type:`connection`, m: :bro:type:`pm_mapping`, success: :bro:type:`bool`)

   Generated for Portmapper request/reply dialogues of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The argument to the request.
   

   :success: True if the request was successful, according to the corresponding
            reply. If no reply was seen, this will be false once the request
            times out.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_getport
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_getport

   :Type: :bro:type:`event` (r: :bro:type:`connection`, pr: :bro:type:`pm_port_request`, p: :bro:type:`port`)

   Generated for Portmapper request/reply dialogues of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :pr: The argument to the request.
   

   :p: The port returned by the server.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_dump pm_request_callit pm_attempt_null pm_attempt_set
      pm_attempt_unset pm_attempt_getport pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_dump

   :Type: :bro:type:`event` (r: :bro:type:`connection`, m: :bro:type:`pm_mappings`)

   Generated for Portmapper request/reply dialogues of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :m: The mappings returned by the server.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_callit pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_request_callit

   :Type: :bro:type:`event` (r: :bro:type:`connection`, call: :bro:type:`pm_callit_request`, p: :bro:type:`port`)

   Generated for Portmapper request/reply dialogues of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :call: The argument to the request.
   

   :p: The port value returned by the call.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_attempt_null
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_null

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`)

   Generated for failed Portmapper requests of type *null*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_set pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_set

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, m: :bro:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *set*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :m: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_unset pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_unset

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, m: :bro:type:`pm_mapping`)

   Generated for failed Portmapper requests of type *unset*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :m: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_getport
      pm_attempt_dump pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_getport

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, pr: :bro:type:`pm_port_request`)

   Generated for failed Portmapper requests of type *getport*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :pr: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset pm_attempt_dump
      pm_attempt_callit pm_bad_port rpc_call rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_dump

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`)

   Generated for failed Portmapper requests of type *dump*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_callit pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_attempt_callit

   :Type: :bro:type:`event` (r: :bro:type:`connection`, status: :bro:type:`rpc_status`, call: :bro:type:`pm_callit_request`)

   Generated for failed Portmapper requests of type *callit*.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :call: The argument to the original request.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_bad_port rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: pm_bad_port

   :Type: :bro:type:`event` (r: :bro:type:`connection`, bad_p: :bro:type:`count`)

   Generated for Portmapper requests or replies that include an invalid port
   number. Since ports are represented by unsigned 4-byte integers, they can
   stray outside the allowed range of 0--65535 by being >= 65536. If so, this
   event is generated.
   
   Portmapper is a service running on top of RPC. See `Wikipedia
   <http://en.wikipedia.org/wiki/Portmap>`__ for more information about the
   service.
   

   :r: The RPC connection.
   

   :bad_p: The invalid port value.
   
   .. bro:see:: pm_request_null pm_request_set pm_request_unset
      pm_request_getport pm_request_dump pm_request_callit
      pm_attempt_null pm_attempt_set pm_attempt_unset
      pm_attempt_getport pm_attempt_dump pm_attempt_callit rpc_call
      rpc_dialogue rpc_reply
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: rpc_dialogue

   :Type: :bro:type:`event` (c: :bro:type:`connection`, prog: :bro:type:`count`, ver: :bro:type:`count`, proc: :bro:type:`count`, status: :bro:type:`rpc_status`, start_time: :bro:type:`time`, call_len: :bro:type:`count`, reply_len: :bro:type:`count`)

   Generated for RPC request/reply *pairs*. The RPC analyzer associates request
   and reply by their transaction identifiers and raises this event once both
   have been seen. If there's not a reply, this event will still be generated
   eventually on timeout. In that case, *status* will be set to
   :bro:enum:`RPC_TIMEOUT`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :prog: The remote program to call.
   

   :ver: The version of the remote program to call.
   

   :proc: The procedure of the remote program to call.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :start_time: The time when the *call* was seen.
   

   :call_len: The size of the *call_body* PDU.
   

   :reply_len: The size of the *reply_body* PDU.
   
   .. bro:see:: rpc_call rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: rpc_call

   :Type: :bro:type:`event` (c: :bro:type:`connection`, xid: :bro:type:`count`, prog: :bro:type:`count`, ver: :bro:type:`count`, proc: :bro:type:`count`, call_len: :bro:type:`count`)

   Generated for RPC *call* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :xid: The transaction identifier allowing to match requests with replies.
   

   :prog: The remote program to call.
   

   :ver: The version of the remote program to call.
   

   :proc: The procedure of the remote program to call.
   

   :call_len: The size of the *call_body* PDU.
   
   .. bro:see::  rpc_dialogue rpc_reply dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: rpc_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, xid: :bro:type:`count`, status: :bro:type:`rpc_status`, reply_len: :bro:type:`count`)

   Generated for RPC *reply* messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/ONC_RPC>`__ for more information
   about the ONC RPC protocol.
   

   :c: The connection.
   

   :xid: The transaction identifier allowing to match requests with replies.
   

   :status: The status of the reply, which should be one of the index values of
           :bro:id:`RPC_status`.
   

   :reply_len: The size of the *reply_body* PDU.
   
   .. bro:see:: rpc_call rpc_dialogue  dce_rpc_bind dce_rpc_message dce_rpc_request
      dce_rpc_response rpc_timeout
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to add a
      call to :bro:see:`Analyzer::register_for_ports` or a DPD payload
      signature.

.. bro:id:: mount_proc_null

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`)

   Generated for MOUNT3 request/reply dialogues of type *null*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_mnt

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, req: :bro:type:`MOUNT3::dirmntargs_t`, rep: :bro:type:`MOUNT3::mnt_reply_t`)

   Generated for MOUNT3 request/reply dialogues of type *mnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   

   :rep: The response returned in the reply. The values may not be valid if the
        request was unsuccessful.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_umnt

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, req: :bro:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_umnt_all

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, req: :bro:type:`MOUNT3::dirmntargs_t`)

   Generated for MOUNT3 request/reply dialogues of type *umnt_all*. The event is
   generated once we have either seen both the request and its corresponding
   reply, or an unanswered request has timed out.
   MOUNT is a service running on top of RPC.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :req:  The arguments passed in the request.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_proc_not_implemented

   :Type: :bro:type:`event` (c: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`, proc: :bro:type:`MOUNT3::proc_t`)

   Generated for MOUNT3 request/reply dialogues of a type that Bro's MOUNTv3
   analyzer does not implement.
   

   :c: The RPC connection.
   

   :info: Reports the status of the dialogue, along with some meta information.
   

   :proc: The procedure called that Bro does not implement.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: mount_reply_status

   :Type: :bro:type:`event` (n: :bro:type:`connection`, info: :bro:type:`MOUNT3::info_t`)

   Generated for each MOUNT3 reply message received, reporting just the
   status included.
   

   :n: The connection.
   

   :info: Reports the status included in the reply.
   
   .. bro:see:: mount_proc_mnt mount_proc_umnt
      mount_proc_umnt_all mount_proc_not_implemented
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

Bro::SIP
--------

SIP analyzer UDP-only

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_SIP`

Events
++++++

.. bro:id:: sip_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, method: :bro:type:`string`, original_URI: :bro:type:`string`, version: :bro:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` requests, used in Voice over IP (VoIP).
   
   This event is generated as soon as a request's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :method: The :abbr:`SIP (Session Initiation Protocol)` method extracted from the request (e.g., ``REGISTER``, ``NOTIFY``).
   

   :original_URI: The unprocessed URI as specified in the request.
   

   :version: The version number specified in the request (e.g., ``2.0``).
   
   .. bro:see:: sip_reply sip_header sip_all_headers sip_begin_entity sip_end_entity

.. bro:id:: sip_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`, code: :bro:type:`count`, reason: :bro:type:`string`)

   Generated for :abbr:`SIP (Session Initiation Protocol)` replies, used in Voice over IP (VoIP).
   
   This event is generated as soon as a reply's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :version: The :abbr:`SIP (Session Initiation Protocol)` version in use.
   

   :code: The response code.
   

   :reason: Textual details for the response code.
   
   .. bro:see:: sip_request sip_header sip_all_headers sip_begin_entity sip_end_entity

.. bro:id:: sip_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, name: :bro:type:`string`, value: :bro:type:`string`)

   Generated for each :abbr:`SIP (Session Initiation Protocol)` header.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the header came from the originator.
   

   :name: Header name.
   

   :value: Header value.
   
   .. bro:see:: sip_request sip_reply sip_all_headers sip_begin_entity sip_end_entity

.. bro:id:: sip_all_headers

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, hlist: :bro:type:`mime_header_list`)

   Generated once for all :abbr:`SIP (Session Initiation Protocol)` headers from the originator or responder.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the headers came from the originator.
   

   :hlist: All the headers, and their values
   
   .. bro:see:: sip_request sip_reply sip_header sip_begin_entity sip_end_entity

.. bro:id:: sip_begin_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated at the beginning of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   This event is generated as soon as a message's initial line has been parsed.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the message came from the originator.
   
   .. bro:see:: sip_request sip_reply sip_header sip_all_headers sip_end_entity

.. bro:id:: sip_end_entity

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated at the end of a :abbr:`SIP (Session Initiation Protocol)` message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Session_Initiation_Protocol>`__
   for more information about the :abbr:`SIP (Session Initiation Protocol)` protocol.
   

   :c: The connection.
   

   :is_orig: Whether the message came from the originator.
   
   .. bro:see:: sip_request sip_reply sip_header sip_all_headers sip_begin_entity

Bro::SMB
--------

SMB analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTS_SMB`

:bro:enum:`Analyzer::ANALYZER_SMB`

Options/Constants
+++++++++++++++++

.. bro:id:: SMB::pipe_filenames

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "srvsvc",
         "winreg",
         "netdfs",
         "MsFteWds",
         "samr",
         "spoolss",
         "wkssvc",
         "lsarpc"
      }

   A set of file names used as named pipes over SMB. This
   only comes into play as a heuristic to identify named
   pipes when the drive mapping wasn't seen by Bro.
   
   .. bro:see:: smb_pipe_connect_heuristic

Types
+++++

.. bro:type:: SMB1::NegotiateResponse

   :Type: :bro:type:`record`

      core: :bro:type:`SMB1::NegotiateResponseCore` :bro:attr:`&optional`
         If the server does not understand any of the dialect strings, or if 
         PC NETWORK PROGRAM 1.0 is the chosen dialect.

      lanman: :bro:type:`SMB1::NegotiateResponseLANMAN` :bro:attr:`&optional`
         If the chosen dialect is greater than core up to and including
         LANMAN 2.1.

      ntlm: :bro:type:`SMB1::NegotiateResponseNTLM` :bro:attr:`&optional`
         If the chosen dialect is NT LM 0.12.


.. bro:type:: SMB1::NegotiateResponseCore

   :Type: :bro:type:`record`

      dialect_index: :bro:type:`count`
         Index of selected dialect


.. bro:type:: SMB1::NegotiateResponseLANMAN

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words (should be 13)

      dialect_index: :bro:type:`count`
         Index of selected dialect

      security_mode: :bro:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :bro:type:`count`
         Max transmit buffer size (>= 1024)

      max_mpx_count: :bro:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :bro:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      raw_mode: :bro:type:`SMB1::NegotiateRawMode`
         Raw mode

      session_key: :bro:type:`count`
         Unique token identifying this session

      server_time: :bro:type:`time`
         Current date and time at server

      encryption_key: :bro:type:`string`
         The challenge encryption key

      primary_domain: :bro:type:`string`
         The server's primary domain


.. bro:type:: SMB1::NegotiateResponseNTLM

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words (should be 17)

      dialect_index: :bro:type:`count`
         Index of selected dialect

      security_mode: :bro:type:`SMB1::NegotiateResponseSecurity`
         Security mode

      max_buffer_size: :bro:type:`count`
         Max transmit buffer size

      max_mpx_count: :bro:type:`count`
         Max pending multiplexed requests

      max_number_vcs: :bro:type:`count`
         Max number of virtual circuits (VCs - transport-layer connections)
         between client and server

      max_raw_size: :bro:type:`count`
         Max raw buffer size

      session_key: :bro:type:`count`
         Unique token identifying this session

      capabilities: :bro:type:`SMB1::NegotiateCapabilities`
         Server capabilities

      server_time: :bro:type:`time`
         Current date and time at server

      encryption_key: :bro:type:`string` :bro:attr:`&optional`
         The challenge encryption key.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      domain_name: :bro:type:`string` :bro:attr:`&optional`
         The name of the domain.
         Present only for non-extended security (i.e. capabilities$extended_security = F)

      guid: :bro:type:`string` :bro:attr:`&optional`
         A globally unique identifier assigned to the server.
         Present only for extended security (i.e. capabilities$extended_security = T)

      security_blob: :bro:type:`string`
         Opaque security blob associated with the security package if capabilities$extended_security = T
         Otherwise, the challenge for challenge/response authentication.


.. bro:type:: SMB1::NegotiateResponseSecurity

   :Type: :bro:type:`record`

      user_level: :bro:type:`bool`
         This indicates whether the server, as a whole, is operating under
         Share Level or User Level security.

      challenge_response: :bro:type:`bool`
         This indicates whether or not the server supports Challenge/Response
         authentication. If the bit is false, then plaintext passwords must
         be used.

      signatures_enabled: :bro:type:`bool` :bro:attr:`&optional`
         This indicates if the server is capable of performing MAC message
         signing. Note: Requires NT LM 0.12 or later.

      signatures_required: :bro:type:`bool` :bro:attr:`&optional`
         This indicates if the server is requiring the use of a MAC in each
         packet. If false, message signing is optional. Note: Requires NT LM 0.12
         or later.


.. bro:type:: SMB1::NegotiateRawMode

   :Type: :bro:type:`record`

      read_raw: :bro:type:`bool`
         Read raw supported

      write_raw: :bro:type:`bool`
         Write raw supported


.. bro:type:: SMB1::NegotiateCapabilities

   :Type: :bro:type:`record`

      raw_mode: :bro:type:`bool`
         The server supports SMB_COM_READ_RAW and SMB_COM_WRITE_RAW

      mpx_mode: :bro:type:`bool`
         The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX

      unicode: :bro:type:`bool`
         The server supports unicode strings

      large_files: :bro:type:`bool`
         The server supports large files with 64 bit offsets

      nt_smbs: :bro:type:`bool`
         The server supports the SMBs particilar to the NT LM 0.12 dialect. Implies nt_find.

      rpc_remote_apis: :bro:type:`bool`
         The server supports remote admin API requests via DCE-RPC

      status32: :bro:type:`bool`
         The server can respond with 32 bit status codes in Status.Status

      level_2_oplocks: :bro:type:`bool`
         The server supports level 2 oplocks

      lock_and_read: :bro:type:`bool`
         The server supports SMB_COM_LOCK_AND_READ

      nt_find: :bro:type:`bool`
         Reserved

      dfs: :bro:type:`bool`
         The server is DFS aware

      infolevel_passthru: :bro:type:`bool`
         The server supports NT information level requests passing through

      large_readx: :bro:type:`bool`
         The server supports large SMB_COM_READ_ANDX (up to 64k)

      large_writex: :bro:type:`bool`
         The server supports large SMB_COM_WRITE_ANDX (up to 64k)

      unix: :bro:type:`bool`
         The server supports CIFS Extensions for UNIX

      bulk_transfer: :bro:type:`bool`
         The server supports SMB_BULK_READ, SMB_BULK_WRITE
         Note: No known implementations support this

      compressed_data: :bro:type:`bool`
         The server supports compressed data transfer. Requires bulk_transfer.
         Note: No known implementations support this

      extended_security: :bro:type:`bool`
         The server supports extended security exchanges	


.. bro:type:: SMB1::SessionSetupAndXRequest

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words
            - 10 for pre NT LM 0.12
            - 12 for NT LM 0.12 with extended security
            - 13 for NT LM 0.12 without extended security

      max_buffer_size: :bro:type:`count`
         Client maximum buffer size

      max_mpx_count: :bro:type:`count`
         Actual maximum multiplexed pending request

      vc_number: :bro:type:`count`
         Virtual circuit number. First VC == 0

      session_key: :bro:type:`count`
         Session key (valid iff vc_number > 0)

      native_os: :bro:type:`string`
         Client's native operating system

      native_lanman: :bro:type:`string`
         Client's native LAN Manager type

      account_name: :bro:type:`string` :bro:attr:`&optional`
         Account name
         Note: not set for NT LM 0.12 with extended security

      account_password: :bro:type:`string` :bro:attr:`&optional`
         If challenge/response auth is not being used, this is the password.
         Otherwise, it's the response to the server's challenge.
         Note: Only set for pre NT LM 0.12

      primary_domain: :bro:type:`string` :bro:attr:`&optional`
         Client's primary domain, if known
         Note: not set for NT LM 0.12 with extended security

      case_insensitive_password: :bro:type:`string` :bro:attr:`&optional`
         Case insensitive password
         Note: only set for NT LM 0.12 without extended security

      case_sensitive_password: :bro:type:`string` :bro:attr:`&optional`
         Case sensitive password
         Note: only set for NT LM 0.12 without extended security

      security_blob: :bro:type:`string` :bro:attr:`&optional`
         Security blob
         Note: only set for NT LM 0.12 with extended security

      capabilities: :bro:type:`SMB1::SessionSetupAndXCapabilities` :bro:attr:`&optional`
         Client capabilities
         Note: only set for NT LM 0.12


.. bro:type:: SMB1::SessionSetupAndXResponse

   :Type: :bro:type:`record`

      word_count: :bro:type:`count`
         Count of parameter words (should be 3 for pre NT LM 0.12 and 4 for NT LM 0.12)

      is_guest: :bro:type:`bool` :bro:attr:`&optional`
         Were we logged in as a guest user?

      native_os: :bro:type:`string` :bro:attr:`&optional`
         Server's native operating system

      native_lanman: :bro:type:`string` :bro:attr:`&optional`
         Server's native LAN Manager type

      primary_domain: :bro:type:`string` :bro:attr:`&optional`
         Server's primary domain

      security_blob: :bro:type:`string` :bro:attr:`&optional`
         Security blob if NTLM


.. bro:type:: SMB1::SessionSetupAndXCapabilities

   :Type: :bro:type:`record`

      unicode: :bro:type:`bool`
         The client can use unicode strings

      large_files: :bro:type:`bool`
         The client can deal with files having 64 bit offsets

      nt_smbs: :bro:type:`bool`
         The client understands the SMBs introduced with NT LM 0.12
         Implies nt_find

      status32: :bro:type:`bool`
         The client can receive 32 bit errors encoded in Status.Status

      level_2_oplocks: :bro:type:`bool`
         The client understands Level II oplocks

      nt_find: :bro:type:`bool`
         Reserved. Implied by nt_smbs.


.. bro:type:: SMB1::Trans_Sec_Args

   :Type: :bro:type:`record`

      total_param_count: :bro:type:`count`
         Total parameter count

      total_data_count: :bro:type:`count`
         Total data count

      param_count: :bro:type:`count`
         Parameter count

      param_offset: :bro:type:`count`
         Parameter offset

      param_displacement: :bro:type:`count`
         Parameter displacement

      data_count: :bro:type:`count`
         Data count

      data_offset: :bro:type:`count`
         Data offset

      data_displacement: :bro:type:`count`
         Data displacement


.. bro:type:: SMB1::Find_First2_Request_Args

   :Type: :bro:type:`record`

      search_attrs: :bro:type:`count`
         File attributes to apply as a constraint to the search

      search_count: :bro:type:`count`
         Max search results

      flags: :bro:type:`count`
         Misc. flags for how the server should manage the transaction
         once results are returned

      info_level: :bro:type:`count`
         How detailed the information returned in the results should be

      search_storage_type: :bro:type:`count`
         Specify whether to search for directories or files

      file_name: :bro:type:`string`
         The string to serch for (note: may contain wildcards)


.. bro:type:: SMB1::Find_First2_Response_Args

   :Type: :bro:type:`record`

      sid: :bro:type:`count`
         The server generated search identifier

      search_count: :bro:type:`count`
         Number of results returned by the search

      end_of_search: :bro:type:`bool`
         Whether or not the search can be continued using
         the TRANS2_FIND_NEXT2 transaction

      ext_attr_error: :bro:type:`string` :bro:attr:`&optional`
         An extended attribute name that couldn't be retrieved


.. bro:type:: SMB1::Trans2_Args

   :Type: :bro:type:`record`

      total_param_count: :bro:type:`count`
         Total parameter count

      total_data_count: :bro:type:`count`
         Total data count

      max_param_count: :bro:type:`count`
         Max parameter count

      max_data_count: :bro:type:`count`
         Max data count

      max_setup_count: :bro:type:`count`
         Max setup count

      flags: :bro:type:`count`
         Flags

      trans_timeout: :bro:type:`count`
         Timeout

      param_count: :bro:type:`count`
         Parameter count

      param_offset: :bro:type:`count`
         Parameter offset

      data_count: :bro:type:`count`
         Data count

      data_offset: :bro:type:`count`
         Data offset

      setup_count: :bro:type:`count`
         Setup count


.. bro:type:: SMB1::Trans2_Sec_Args

   :Type: :bro:type:`record`

      total_param_count: :bro:type:`count`
         Total parameter count

      total_data_count: :bro:type:`count`
         Total data count

      param_count: :bro:type:`count`
         Parameter count

      param_offset: :bro:type:`count`
         Parameter offset

      param_displacement: :bro:type:`count`
         Parameter displacement

      data_count: :bro:type:`count`
         Data count

      data_offset: :bro:type:`count`
         Data offset

      data_displacement: :bro:type:`count`
         Data displacement

      FID: :bro:type:`count`
         File ID


.. bro:type:: SMB2::CloseResponse

   :Type: :bro:type:`record`

      alloc_size: :bro:type:`count`
         The size, in bytes of the data that is allocated to the file.

      eof: :bro:type:`count`
         The size, in bytes, of the file.

      times: :bro:type:`SMB::MACTimes`
         The creation, last access, last write, and change times.

      attrs: :bro:type:`SMB2::FileAttrs`
         The attributes of the file.

   The response to an SMB2 *close* request, which is used by the client to close an instance
   of a file that was opened previously.
   
   For more information, see MS-SMB2:2.2.16
   
   .. bro:see:: smb2_close_response

.. bro:type:: SMB2::CreateRequest

   :Type: :bro:type:`record`

      filename: :bro:type:`string`
         Name of the file

      disposition: :bro:type:`count`
         Defines the action the server MUST take if the file that is specified already exists.

      create_options: :bro:type:`count`
         Specifies the options to be applied when creating or opening the file.

   The request sent by the client to request either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   
   .. bro:see:: smb2_create_request

.. bro:type:: SMB2::CreateResponse

   :Type: :bro:type:`record`

      file_id: :bro:type:`SMB2::GUID`
         The SMB2 GUID for the file.

      size: :bro:type:`count`
         Size of the file.

      times: :bro:type:`SMB::MACTimes`
         Timestamps associated with the file in question.

      attrs: :bro:type:`SMB2::FileAttrs`
         File attributes.

      create_action: :bro:type:`count`
         The action taken in establishing the open.

   The response to an SMB2 *create_request* request, which is sent by the client to request
   either creation of or access to a file.
   
   For more information, see MS-SMB2:2.2.14
   
   .. bro:see:: smb2_create_response

.. bro:type:: SMB2::NegotiateResponse

   :Type: :bro:type:`record`

      dialect_revision: :bro:type:`count`
         The preferred common SMB2 Protocol dialect number from the array that was sent in the SMB2
         NEGOTIATE Request.

      security_mode: :bro:type:`count`
         The security mode field specifies whether SMB signing is enabled, required at the server, or both.

      server_guid: :bro:type:`string`
         A globally unique identifier that is generate by the server to uniquely identify the server.

      system_time: :bro:type:`time`
         The system time of the SMB2 server when the SMB2 NEGOTIATE Request was processed.

      server_start_time: :bro:type:`time`
         The SMB2 server start time.

      negotiate_context_count: :bro:type:`count`
         The number of negotiate context values in SMB v. 3.1.1, otherwise reserved to 0.

      negotiate_context_values: :bro:type:`SMB2::NegotiateContextValues`
         An array of context values in SMB v. 3.1.1.

   The response to an SMB2 *negotiate* request, which is used by tghe client to notify the server
   what dialects of the SMB2 protocol the client understands.
   
   For more information, see MS-SMB2:2.2.4
   
   .. bro:see:: smb2_negotiate_response

.. bro:type:: SMB2::SessionSetupRequest

   :Type: :bro:type:`record`

      security_mode: :bro:type:`count`
         The security mode field specifies whether SMB signing is enabled or required at the client.

   The request sent by the client to request a new authenticated session
   within a new or existing SMB 2 Protocol transport connection to the server.
   
   For more information, see MS-SMB2:2.2.5
   
   .. bro:see:: smb2_session_setup_request

.. bro:type:: SMB2::SessionSetupResponse

   :Type: :bro:type:`record`

      flags: :bro:type:`SMB2::SessionSetupFlags`
         Additional information about the session

   The response to an SMB2 *session_setup* request, which is sent by the client to request a
   new authenticated session within a new or existing SMB 2 Protocol transport connection
   to the server.
   
   For more information, see MS-SMB2:2.2.6
   
   .. bro:see:: smb2_session_setup_response

.. bro:type:: SMB2::SessionSetupFlags

   :Type: :bro:type:`record`

      guest: :bro:type:`bool`
         If set, the client has been authenticated as a guest user.

      anonymous: :bro:type:`bool`
         If set, the client has been authenticated as an anonymous user.

      encrypt: :bro:type:`bool`
         If set, the server requires encryption of messages on this session.

   A flags field that indicates additional information about the session that's sent in the
   *session_setup* response.
   
   For more information, see MS-SMB2:2.2.6
   
   .. bro:see:: smb2_session_setup_response

.. bro:type:: SMB2::TreeConnectResponse

   :Type: :bro:type:`record`

      share_type: :bro:type:`count`
         The type of share being accessed. Physical disk, named pipe, or printer.

   The response to an SMB2 *tree_connect* request, which is sent by the client to request
   access to a particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   
   .. bro:see:: smb2_tree_connect_response

.. bro:type:: SMB2::Transform_header

   :Type: :bro:type:`record`

      signature: :bro:type:`string`
         The 16-byte signature of the encrypted message, generated by using Session.EncryptionKey.

      nonce: :bro:type:`string`
         An implementation specific value assigned for every encrypted message.

      orig_msg_size: :bro:type:`count`
         The size, in bytes, of the SMB2 message.

      flags: :bro:type:`count`
         A flags field, interpreted in different ways depending of the SMB2 dialect.

      session_id: :bro:type:`count`
         A value that uniquely identifies the established session for the command.

   An SMB2 transform header (for SMB 3.x dialects with encryption enabled).
   
   For more information, see MS-SMB2:2.2.41
   
   .. bro:see:: smb2_transform_header smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. bro:type:: SMB::MACTimes

   :Type: :bro:type:`record`

      modified: :bro:type:`time` :bro:attr:`&log`
         The time when data was last written to the file.

      accessed: :bro:type:`time` :bro:attr:`&log`
         The time when the file was last accessed.

      created: :bro:type:`time` :bro:attr:`&log`
         The time the file was created.

      changed: :bro:type:`time` :bro:attr:`&log`
         The time when the file was last modified.
   :Attributes: :bro:attr:`&log`

   MAC times for a file.
   
   For more information, see MS-SMB2:2.2.16
   
   .. bro:see:: smb1_nt_create_andx_response smb2_create_response

.. bro:type:: SMB1::Header

   :Type: :bro:type:`record`

      command: :bro:type:`count`
         The command number

      status: :bro:type:`count`
         The status code

      flags: :bro:type:`count`
         Flag set 1

      flags2: :bro:type:`count`
         Flag set 2

      tid: :bro:type:`count`
         Tree ID

      pid: :bro:type:`count`
         Process ID

      uid: :bro:type:`count`
         User ID

      mid: :bro:type:`count`
         Multiplex ID

   An SMB1 header.
   
   .. bro:see:: smb1_message smb1_empty_response smb1_error
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

.. bro:type:: SMB2::Header

   :Type: :bro:type:`record`

      credit_charge: :bro:type:`count`
         The number of credits that this request consumes

      status: :bro:type:`count`
         In a request, this is an indication to the server about the client's channel
         change. In a response, this is the status field

      command: :bro:type:`count`
         The command code of the packet

      credits: :bro:type:`count`
         The number of credits the client is requesting, or the number of credits
         granted to the client in a response.

      flags: :bro:type:`count`
         A flags field, which indicates how to process the operation (e.g. asynchronously)

      message_id: :bro:type:`count`
         A value that uniquely identifies the message request/response pair across all
         messages that are sent on the same transport protocol connection

      process_id: :bro:type:`count`
         A value that uniquely identifies the process that generated the event.

      tree_id: :bro:type:`count`
         A value that uniquely identifies the tree connect for the command.

      session_id: :bro:type:`count`
         A value that uniquely identifies the established session for the command.

      signature: :bro:type:`string`
         The 16-byte signature of the message, if SMB2_FLAGS_SIGNED is set in the ``flags``
         field.

   An SMB2 header.
   
   For more information, see MS-SMB2:2.2.1.1 and MS-SMB2:2.2.1.2
   
   .. bro:see:: smb2_message smb2_close_request smb2_close_response
      smb2_create_request smb2_create_response smb2_negotiate_request
      smb2_negotiate_response smb2_read_request
      smb2_session_setup_request smb2_session_setup_response
      smb2_file_rename smb2_file_delete
      smb2_tree_connect_request smb2_tree_connect_response
      smb2_write_request

.. bro:type:: SMB2::GUID

   :Type: :bro:type:`record`

      persistent: :bro:type:`count`
         A file handle that remains persistent when reconnected after a disconnect

      volatile: :bro:type:`count`
         A file handle that can be changed when reconnected after a disconnect

   An SMB2 globally unique identifier which identifies a file.
   
   For more information, see MS-SMB2:2.2.14.1
   
   .. bro:see:: smb2_close_request smb2_create_response smb2_read_request
      smb2_file_rename smb2_file_delete smb2_write_request

.. bro:type:: SMB2::FileAttrs

   :Type: :bro:type:`record`

      read_only: :bro:type:`bool`
         The file is read only. Applications can read the file but cannot
         write to it or delete it.

      hidden: :bro:type:`bool`
         The file is hidden. It is not to be included in an ordinary directory listing.

      system: :bro:type:`bool`
         The file is part of or is used exclusively by the operating system.

      directory: :bro:type:`bool`
         The file is a directory.

      archive: :bro:type:`bool`
         The file has not been archived since it was last modified. Applications use
         this attribute to mark files for backup or removal.

      normal: :bro:type:`bool`
         The file has no other attributes set. This attribute is valid only if used alone.

      temporary: :bro:type:`bool`
         The file is temporary. This is a hint to the cache manager that it does not need
         to flush the file to backing storage.

      sparse_file: :bro:type:`bool`
         A file that is a sparse file.

      reparse_point: :bro:type:`bool`
         A file or directory that has an associated reparse point.

      compressed: :bro:type:`bool`
         The file or directory is compressed. For a file, this means that all of the data
         in the file is compressed. For a directory, this means that compression is the
         default for newly created files and subdirectories.

      offline: :bro:type:`bool`
         The data in this file is not available immediately. This attribute indicates that
         the file data is physically moved to offline storage. This attribute is used by
         Remote Storage, which is hierarchical storage management software.

      not_content_indexed: :bro:type:`bool`
         A file or directory that is not indexed by the content indexing service.

      encrypted: :bro:type:`bool`
         A file or directory that is encrypted. For a file, all data streams in the file
         are encrypted. For a directory, encryption is the default for newly created files
         and subdirectories.

      integrity_stream: :bro:type:`bool`
         A file or directory that is configured with integrity support. For a file, all
         data streams in the file have integrity support. For a directory, integrity support
         is the default for newly created files and subdirectories, unless the caller
         specifies otherwise.

      no_scrub_data: :bro:type:`bool`
         A file or directory that is configured to be excluded from the data integrity scan.

   A series of boolean flags describing basic and extended file attributes for SMB2.
   
   For more information, see MS-CIFS:2.2.1.2.3 and MS-FSCC:2.6
   
   .. bro:see:: smb2_create_response

.. bro:type:: SMB2::PreAuthIntegrityCapabilities

   :Type: :bro:type:`record`

      hash_alg_count: :bro:type:`count`
         The number of hash algorithms.

      salt_length: :bro:type:`count`
         The salt length.

      hash_alg: :bro:type:`vector` of :bro:type:`count`
         An array of hash algorithms (counts).

      salt: :bro:type:`string`
         The salt.

   Preauthentication information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.1
   

.. bro:type:: SMB2::EncryptionCapabilities

   :Type: :bro:type:`record`

      cipher_count: :bro:type:`count`
         The number of ciphers.

      ciphers: :bro:type:`vector` of :bro:type:`count`
         An array of ciphers.

   Encryption information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.2
   

.. bro:type:: SMB2::CompressionCapabilities

   :Type: :bro:type:`record`

      alg_count: :bro:type:`count`
         The number of algorithms.

      algs: :bro:type:`vector` of :bro:type:`count`
         An array of compression algorithms.

   Compression information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1.3
   

.. bro:type:: SMB2::NegotiateContextValue

   :Type: :bro:type:`record`

      context_type: :bro:type:`count`
         Specifies the type of context (preauth or encryption).

      data_length: :bro:type:`count`
         The length in byte of the data field.

      preauth_info: :bro:type:`SMB2::PreAuthIntegrityCapabilities` :bro:attr:`&optional`
         The preauthentication information.

      encryption_info: :bro:type:`SMB2::EncryptionCapabilities` :bro:attr:`&optional`
         The encryption information.

      compression_info: :bro:type:`SMB2::CompressionCapabilities` :bro:attr:`&optional`
         The compression information.

      netname: :bro:type:`string` :bro:attr:`&optional`
         Indicates the server name the client must connect to.

   The context type information as defined in SMB v. 3.1.1
   
   For more information, see MS-SMB2:2.3.1
   

.. bro:type:: SMB2::NegotiateContextValues

   :Type: :bro:type:`vector` of :bro:type:`SMB2::NegotiateContextValue`


Events
++++++

.. bro:id:: smb1_check_directory_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, directory_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *check directory*. This is used by the client to verify that
   a specified path resolves to a valid directory on the server.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :directory_name: The directory name to check for existence.
   
   .. bro:see:: smb1_message smb1_check_directory_response

.. bro:id:: smb1_check_directory_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *check directory*. This is the server response to the
   *check directory* request.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. bro:see:: smb1_message smb1_check_directory_request

.. bro:id:: smb1_close_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *close*. This is used by the client to close an instance of an object
   associated with a valid file ID.
   
   For more information, see MS-CIFS:2.2.4.5
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_id: The file identifier being closed.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_create_directory_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, directory_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is used by the client to
   create a new directory on the server, relative to a connected share.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :directory_name: The name of the directory to create.
   
   .. bro:see:: smb1_message smb1_create_directory_response smb1_transaction2_request

.. bro:id:: smb1_create_directory_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is the server response
   to the *create directory* request.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. bro:see:: smb1_message smb1_create_directory_request smb1_transaction2_request

.. bro:id:: smb1_echo_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, echo_count: :bro:type:`count`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *echo*. This is sent by the client to test the transport layer
   connection with the server.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :echo_count: The number of times the server should echo the data back.
   

   :data: The data for the server to echo.
   
   .. bro:see:: smb1_message smb1_echo_response

.. bro:id:: smb1_echo_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, seq_num: :bro:type:`count`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *echo*. This is the server response to the *echo* request.
   
   For more information, see MS-CIFS:2.2.4.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :seq_num: The sequence number of this echo reply.
   

   :data: The data echoed back from the client.
   
   .. bro:see:: smb1_message smb1_echo_request

.. bro:id:: smb1_logoff_andx

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *logoff andx*. This is used by the client to logoff the user
   connection represented by UID in the SMB Header. The server releases all locks and closes
   all files currently open by this user, disconnects all tree connects, cancels any outstanding
   requests for this UID, and invalidates the UID.
   
   For more information, see MS-CIFS:2.2.4.54
   

   :c: The connection.
   

   :is_orig: Indicates which host sent the logoff message.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_negotiate_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, dialects: :bro:type:`string_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *negotiate*. This is sent by the client to initiate an SMB
   connection between the client and the server. A *negotiate* exchange MUST be completed
   before any other SMB messages are sent to the server.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :dialects: The SMB dialects supported by the client.
   
   .. bro:see:: smb1_message smb1_negotiate_response

.. bro:id:: smb1_negotiate_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, response: :bro:type:`SMB1::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *negotiate*. This is the server response to the *negotiate*
   request.
   
   For more information, see MS-CIFS:2.2.4.52
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :response: A record structure containing more information from the response.
   
   .. bro:see:: smb1_message smb1_negotiate_request

.. bro:id:: smb1_nt_create_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt create andx*. This is sent by the client to create and open
   a new file, or to open an existing file, or to open and truncate an existing file to zero
   length, or to create a directory, or to create a connection to a named pipe.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :name: The ``name`` attribute  specified in the message.
   
   .. bro:see:: smb1_message smb1_nt_create_andx_response

.. bro:id:: smb1_nt_create_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`, file_size: :bro:type:`count`, times: :bro:type:`SMB::MACTimes`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *nt create andx*. This is the server response to the
   *nt create andx* request.
   
   For more information, see MS-CIFS:2.2.4.64
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :file_size: Size of the file.
   

   :times: Timestamps associated with the file in question.
   
   .. bro:see:: smb1_message smb1_nt_create_andx_request

.. bro:id:: smb1_nt_cancel_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *nt cancel*. This is sent by the client to request that a currently
   pending request be cancelled.
   
   For more information, see MS-CIFS:2.2.4.65
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_query_information_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, filename: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *query information*. This is a deprecated command which
   has been replaced by the *trans2_query_path_information* subcommand. This is used by the
   client to obtain attribute information about a file.
   
   For more information, see MS-CIFS:2.2.4.9
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :filename: The filename that the client is querying.
   
   .. bro:see:: smb1_message smb1_transaction2_request

.. bro:id:: smb1_read_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`, offset: :bro:type:`count`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *read andx*. This is sent by the client to read bytes from a regular
   file, a named pipe, or a directly accessible device such as a serial port (COM) or printer
   port (LPT).
   
   For more information, see MS-CIFS:2.2.4.42
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_id: The file identifier being written to.
   

   :offset: The byte offset the requested read begins at.
   

   :length: The number of bytes being requested.
   
   .. bro:see:: smb1_message smb1_read_andx_response

.. bro:id:: smb1_read_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, data_len: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *read andx*. This is the server response to the *read andx* request.
   
   For more information, see MS-CIFS:2.2.4.42
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :data_len: The length of data from the requested file.
   
   .. bro:see:: smb1_message smb1_read_andx_request

.. bro:id:: smb1_session_setup_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, request: :bro:type:`SMB1::SessionSetupAndXRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *setup andx*. This is sent by the client to configure an SMB session.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :request: The parsed request data of the SMB message. See init-bare for more details.
   
   .. bro:see:: smb1_message smb1_session_setup_andx_response

.. bro:id:: smb1_session_setup_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, response: :bro:type:`SMB1::SessionSetupAndXResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *setup andx*. This is the server response to the *setup andx* request.
   
   For more information, see MS-CIFS:2.2.4.53
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :response: The parsed response data of the SMB message. See init-bare for more details.
   
   .. bro:see:: smb1_message smb1_session_setup_andx_request

.. bro:id:: smb1_transaction_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, name: :bro:type:`string`, sub_cmd: :bro:type:`count`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :name: A name string that MAY identify the resource (a specific Mailslot or Named Pipe) 
         against which the operation is performed.
   

   :sub_cmd: The sub command, some may be parsed and have their own events.
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field
   
   .. bro:see:: smb1_message smb1_transaction2_request

.. bro:id:: smb1_transaction_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction*. This command serves as the transport for the
   Transaction Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system.
   
   For more information, see MS-CIFS:2.2.4.33.2
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field

.. bro:id:: smb1_transaction_secondary_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Trans_Sec_Args`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction_secondary*. This command
   serves as an additional request data container for the
   Transaction Subprotocol Commands (carried by *transaction* requests).
   
   For more information, see MS-CIFS:2.2.4.34
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :parameters: the SMB_Data.Trans_Parameters field content
   

   :data: the SMB_Data.Trans_Data field content
   

.. bro:id:: smb1_transaction2_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Trans2_Args`, sub_cmd: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2*. This command serves as the transport for the
   Transaction2 Subprotocol Commands. These commands operate on mailslots and named pipes,
   which are interprocess communication endpoints within the CIFS file system. Compared to the
   Transaction Subprotocol Commands, these commands allow clients to set and retrieve Extended
   Attribute key/value pairs, make use of long file names (longer than the original 8.3 format
   names), and perform directory searches, among other tasks.
   
   For more information, see MS-CIFS:2.2.4.46
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :sub_cmd: The sub command, some are parsed and have their own events.
   
   .. bro:see:: smb1_message smb1_trans2_find_first2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request smb1_transaction_request

.. bro:id:: smb1_trans2_find_first2_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Find_First2_Request_Args`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *find first2*. This transaction is used to begin
   a search for file(s) within a directory or for a directory
   
   For more information, see MS-CIFS:2.2.6.2
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :args: A record data structure with arguments given to the command.
   
   .. bro:see:: smb1_message smb1_transaction2_request smb1_trans2_query_path_info_request
      smb1_trans2_get_dfs_referral_request

.. bro:id:: smb1_trans2_query_path_info_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *query path info*. This transaction is used to
   get information about a specific file or directory.
   
   For more information, see MS-CIFS:2.2.6.6
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_name: File name the request is in reference to. 
   
   .. bro:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_get_dfs_referral_request

.. bro:id:: smb1_trans2_get_dfs_referral_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 *transaction2* requests of subtype *get DFS referral*. This transaction is used
   to request a referral for a disk object in DFS.
   
   For more information, see MS-CIFS:2.2.6.16
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_name: File name the request is in reference to.
   
   .. bro:see:: smb1_message smb1_transaction2_request smb1_trans2_find_first2_request
      smb1_trans2_query_path_info_request

.. bro:id:: smb1_transaction2_secondary_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, args: :bro:type:`SMB1::Trans2_Sec_Args`, parameters: :bro:type:`string`, data: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *transaction2 secondary*.
   
   For more information, see MS-CIFS:2.2.4.47.1
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)`
        version 1 message.
   

   :args: arguments of the message (SMB_Parameters.Words)
   

   :parameters: content of the SMB_Data.Trans_Parameters field
   

   :data: content of the SMB_Data.Trans_Data field

.. bro:id:: smb1_tree_connect_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, path: :bro:type:`string`, service: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree connect andx*. This is sent by the client to establish a
   connection to a server share.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :path: The ``path`` attribute specified in the message.
   

   :service: The ``service`` attribute specified in the message.
   
   .. bro:see:: smb1_message smb1_tree_connect_andx_response

.. bro:id:: smb1_tree_connect_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, service: :bro:type:`string`, native_file_system: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *tree connect andx*. This is the server reply to the *tree connect andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.55
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :service: The ``service`` attribute specified in the message.
   

   :native_file_system: The file system of the remote server as indicate by the server.
   
   .. bro:see:: smb1_message smb1_tree_connect_andx_request

.. bro:id:: smb1_tree_disconnect

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   
   For more information, see MS-CIFS:2.2.4.51
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :is_orig: True if the message was from the originator.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_write_andx_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`, offset: :bro:type:`count`, data_len: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *write andx*. This is sent by the client to write bytes to a
   regular file, a named pipe, or a directly accessible I/O device such as a serial port (COM)
   or printer port (LPT).
   
   For more information, see MS-CIFS:2.2.4.43
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :offset: The byte offset into the referenced file data is being written.
   

   :data: The data being written.
   
   .. bro:see:: smb1_message smb1_write_andx_response

.. bro:id:: smb1_write_andx_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, written_bytes: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *write andx*. This is the server response to the *write andx*
   request.
   
   For more information, see MS-CIFS:2.2.4.43
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :written_bytes: The number of bytes the server reported having actually written.
   
   .. bro:see:: smb1_message smb1_write_andx_request

.. bro:id:: smb1_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, is_orig: :bro:type:`bool`)

   Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
   messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Bro's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. bro:see:: smb2_message

.. bro:id:: smb1_empty_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)` version 1 messages
   that indicate an error. This event is triggered by an :abbr:`SMB (Server Message Block)` header
   including a status that signals an error.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   

   :is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. bro:see:: smb1_message

.. bro:id:: smb2_close_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *close*. This is used by the client to close an instance of a
   file that was opened previously with a successful SMB2 CREATE Request.
   
   For more information, see MS-SMB2:2.2.15
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_name: The SMB2 GUID of the file being closed.
   
   .. bro:see:: smb2_message smb2_close_response

.. bro:id:: smb2_close_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::CloseResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *close*. This is sent by the server to indicate that an SMB2 CLOSE
   request was processed successfully.
   
   For more information, see MS-SMB2:2.2.16
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record of attributes returned from the server from the close.
   
   .. bro:see:: smb2_message smb2_close_request

.. bro:id:: smb2_create_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, request: :bro:type:`SMB2::CreateRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *create*. This is sent by the client to request either creation
   of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :request: A record with more information related to the request.
   
   .. bro:see:: smb2_message smb2_create_response

.. bro:id:: smb2_create_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::CreateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *create*. This is sent by the server to notify the client of
   the status of its SMB2 CREATE request.
   
   For more information, see MS-SMB2:2.2.14
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record with more information related to the response.
   
   .. bro:see:: smb2_message smb2_create_request

.. bro:id:: smb2_negotiate_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, dialects: :bro:type:`index_vec`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *negotiate*. This is used by the client to notify the server what
   dialects of the SMB2 Protocol the client understands.
   
   For more information, see MS-SMB2:2.2.3
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :dialects: A vector of the client's supported dialects.
   
   .. bro:see:: smb2_message smb2_negotiate_response

.. bro:id:: smb2_negotiate_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::NegotiateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *negotiate*. This is sent by the server to notify the client of
   the preferred common dialect.
   
   For more information, see MS-SMB2:2.2.4
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: The negotiate response data structure.
   
   .. bro:see:: smb2_message smb2_negotiate_request

.. bro:id:: smb2_read_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, offset: :bro:type:`count`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *read*. This is sent by the client to request a read operation on
   the specified file.
   
   For more information, see MS-SMB2:2.2.19
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The GUID being used for the file.
   

   :offset: How far into the file this read should be taking place.
   

   :length: The number of bytes of the file being read.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_session_setup_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, request: :bro:type:`SMB2::SessionSetupRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *session_setup*. This is sent by the client to request a new
   authenticated session within a new or existing SMB 2 Protocol transport connection to the
   server.
   
   For more information, see MS-SMB2:2.2.5
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :request: A record containing more information related to the request.
   
   .. bro:see:: smb2_message smb2_session_setup_response

.. bro:id:: smb2_session_setup_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::SessionSetupResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *session_setup*. This is sent by the server in response to a
   *session_setup* request.
   
   For more information, see MS-SMB2:2.2.6
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record containing more information related to the response.
   
   .. bro:see:: smb2_message smb2_session_setup_request

.. bro:id:: smb2_file_rename

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, dst_filename: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *rename* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: A GUID to identify the file.
   

   :dst_filename: The filename to rename the file into.
   
   .. bro:see:: smb2_message smb2_file_delete smb2_file_sattr

.. bro:id:: smb2_file_delete

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, delete_pending: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *delete* subtype.
   
   For more information, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :delete_pending: A boolean value to indicate that a file should be deleted 
                   when it's closed if set to T.
   
   .. bro:see:: smb2_message smb2_file_rename smb2_file_sattr

.. bro:id:: smb2_file_sattr

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, times: :bro:type:`SMB::MACTimes`, attrs: :bro:type:`SMB2::FileAttrs`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *set_info* of the *file* subtype
   
   For more infomation, see MS-SMB2:2.2.39
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The SMB2 GUID for the file.
   

   :times: Timestamps associated with the file in question.
   

   :attrs: File attributes.
   
   .. bro:see:: smb2_message smb2_file_rename smb2_file_delete

.. bro:id:: smb2_tree_connect_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, path: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree_connect*. This is sent by a client to request access to a
   particular share on the server.
   
   For more information, see MS-SMB2:2.2.9
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :path: Path of the requested tree.
   
   .. bro:see:: smb2_message smb2_tree_connect_response

.. bro:id:: smb2_tree_connect_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::TreeConnectResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *tree_connect*. This is sent by the server when a *tree_connect*
   request is successfully processed by the server.
   
   For more information, see MS-SMB2:2.2.10
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record with more information related to the response.
   
   .. bro:see:: smb2_message smb2_tree_connect_request

.. bro:id:: smb2_tree_disconnect_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_tree_disconnect_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the server to logically disconnect
   client access to a server resource.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_write_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, file_id: :bro:type:`SMB2::GUID`, offset: :bro:type:`count`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the client to write data to the file or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.21
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :file_id: The GUID being used for the file.
   

   :offset: How far into the file this write should be taking place.
   

   :length: The number of bytes of the file being written.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_write_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, length: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *write*. This is sent by the server in response to a write request or
   named pipe on the server.
   
   For more information, see MS-SMB2:2.2.22
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :length: The number of bytes of the file being written.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_transform_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Transform_header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 3.x *transform_header*. This is used by the client or server when sending
   encrypted messages.
   
   For more information, see MS-SMB2:2.2.41
   

   :c: The connection.
   

   :hdr: The parsed transformed header message, which is starting with \xfdSMB and different from SMB1 and SMB2 headers.
   
   .. bro:see:: smb2_message

.. bro:id:: smb2_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Bro's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :is_orig: True if the message came from the originator side.
   
   .. bro:see:: smb1_message

.. bro:id:: smb_pipe_connect_heuristic

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for :abbr:`SMB (Server Message Block)` connections when a
   named pipe has been detected heuristically.  The case when this comes
   up is when the drive mapping isn't seen so the analyzer is not able
   to determine whether to send the data to the files framework or to
   the DCE_RPC analyzer. This heuristic can be tuned by adding or
   removing "named pipe" names from the :bro:see:`SMB::pipe_filenames`
   const.
   

   :c: The connection.

Bro::SMTP
---------

SMTP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_SMTP`

Events
++++++

.. bro:id:: smtp_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, command: :bro:type:`string`, arg: :bro:type:`string`)

   Generated for client-side SMTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the command is the originator of the TCP
         connection. Note that this is not redundant: the SMTP ``TURN`` command
         allows client and server to flip roles on established SMTP sessions,
         and hence a "request" might still come from the TCP-level responder.
         In practice, however, that will rarely happen as TURN is considered
         insecure and rarely used.
   

   :command: The request's command, without any arguments.
   

   :arg: The request command's arguments.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_data smtp_reply
   
   .. note:: Bro does not support the newer ETRN extension yet.

.. bro:id:: smtp_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, code: :bro:type:`count`, cmd: :bro:type:`string`, msg: :bro:type:`string`, cont_resp: :bro:type:`bool`)

   Generated for server-side SMTP commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the command is the originator of the TCP
         connection. Note that this is not redundant: the SMTP ``TURN`` command
         allows client and server to flip roles on established SMTP sessions,
         and hence a "reply" might still come from the TCP-level originator. In
         practice, however, that will rarely happen as TURN is considered
         insecure and rarely used.
   

   :code: The reply's numerical code.
   

   :cmd: TODO.
   

   :msg: The reply's textual description.
   

   :cont_resp: True if the reply line is tagged as being continued to the next
         line. If so, further events will be raised and a handler may want to
         reassemble the pieces before processing the response any further.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_data  smtp_request
   
   .. note:: Bro doesn't support the newer ETRN extension yet.

.. bro:id:: smtp_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, data: :bro:type:`string`)

   Generated for DATA transmitted on SMTP sessions. This event is raised for
   subsequent chunks of raw data following the ``DATA`` SMTP command until the
   corresponding end marker ``.`` is seen. A handler may want to reassemble
   the pieces as they come in if stream-analysis is required.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the data is the originator of the TCP
         connection.
   

   :data: The raw data. Note that the size of each chunk is undefined and
         depends on specifics of the underlying TCP connection.
   
   .. bro:see:: mime_all_data mime_all_headers mime_begin_entity mime_content_hash
      mime_end_entity mime_entity_data mime_event mime_one_header mime_segment_data
      smtp_reply smtp_request skip_smtp_data
   
   .. note:: This event receives the unprocessed raw data. There is a separate
      set of ``mime_*`` events that strip out the outer MIME-layer of emails and
      provide structured access to their content.

.. bro:id:: smtp_unexpected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`, detail: :bro:type:`string`)

   Generated for unexpected activity on SMTP sessions. The SMTP analyzer tracks
   the state of SMTP sessions and reports commands and other activity with this
   event that it sees even though it would not expect so at the current point
   of the communication.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`__
   for more information about the SMTP protocol.
   

   :c: The connection.
   

   :is_orig: True if the sender of the unexpected activity is the originator of
         the TCP connection.
   

   :msg: A descriptive message of what was unexpected.
   

   :detail: The actual SMTP line triggering the event.
   
   .. bro:see:: smtp_data  smtp_request smtp_reply

.. bro:id:: smtp_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated if a connection switched to using TLS using STARTTLS or X-ANONYMOUSTLS.
   After this event no more SMTP events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :c: The connection.
   

Functions
+++++++++

.. bro:id:: skip_smtp_data

   :Type: :bro:type:`function` (c: :bro:type:`connection`) : :bro:type:`any`

   Skips SMTP data until the next email in a connection.
   

   :c: The SMTP connection.
   
   .. bro:see:: skip_http_entity_data

Bro::SNMP
---------

SNMP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_SNMP`

Types
+++++

.. bro:type:: SNMP::Header

   :Type: :bro:type:`record`

      version: :bro:type:`count`

      v1: :bro:type:`SNMP::HeaderV1` :bro:attr:`&optional`
         Set when ``version`` is 0.

      v2: :bro:type:`SNMP::HeaderV2` :bro:attr:`&optional`
         Set when ``version`` is 1.

      v3: :bro:type:`SNMP::HeaderV3` :bro:attr:`&optional`
         Set when ``version`` is 3.

   A generic SNMP header data structure that may include data from
   any version of SNMP.  The value of the ``version`` field
   determines what header field is initialized.

.. bro:type:: SNMP::HeaderV1

   :Type: :bro:type:`record`

      community: :bro:type:`string`

   The top-level message data structure of an SNMPv1 datagram, not
   including the PDU data.  See :rfc:`1157`.

.. bro:type:: SNMP::HeaderV2

   :Type: :bro:type:`record`

      community: :bro:type:`string`

   The top-level message data structure of an SNMPv2 datagram, not
   including the PDU data.  See :rfc:`1901`.

.. bro:type:: SNMP::HeaderV3

   :Type: :bro:type:`record`

      id: :bro:type:`count`

      max_size: :bro:type:`count`

      flags: :bro:type:`count`

      auth_flag: :bro:type:`bool`

      priv_flag: :bro:type:`bool`

      reportable_flag: :bro:type:`bool`

      security_model: :bro:type:`count`

      security_params: :bro:type:`string`

      pdu_context: :bro:type:`SNMP::ScopedPDU_Context` :bro:attr:`&optional`

   The top-level message data structure of an SNMPv3 datagram, not
   including the PDU data.  See :rfc:`3412`.

.. bro:type:: SNMP::PDU

   :Type: :bro:type:`record`

      request_id: :bro:type:`int`

      error_status: :bro:type:`int`

      error_index: :bro:type:`int`

      bindings: :bro:type:`SNMP::Bindings`

   A ``PDU`` data structure from either :rfc:`1157` or :rfc:`3416`.

.. bro:type:: SNMP::TrapPDU

   :Type: :bro:type:`record`

      enterprise: :bro:type:`string`

      agent: :bro:type:`addr`

      generic_trap: :bro:type:`int`

      specific_trap: :bro:type:`int`

      time_stamp: :bro:type:`count`

      bindings: :bro:type:`SNMP::Bindings`

   A ``Trap-PDU`` data structure from :rfc:`1157`.

.. bro:type:: SNMP::BulkPDU

   :Type: :bro:type:`record`

      request_id: :bro:type:`int`

      non_repeaters: :bro:type:`count`

      max_repititions: :bro:type:`count`

      bindings: :bro:type:`SNMP::Bindings`

   A ``BulkPDU`` data structure from :rfc:`3416`.

.. bro:type:: SNMP::ScopedPDU_Context

   :Type: :bro:type:`record`

      engine_id: :bro:type:`string`

      name: :bro:type:`string`

   The ``ScopedPduData`` data structure of an SNMPv3 datagram, not
   including the PDU data (i.e. just the "context" fields).
   See :rfc:`3412`.

.. bro:type:: SNMP::ObjectValue

   :Type: :bro:type:`record`

      tag: :bro:type:`count`

      oid: :bro:type:`string` :bro:attr:`&optional`

      signed: :bro:type:`int` :bro:attr:`&optional`

      unsigned: :bro:type:`count` :bro:attr:`&optional`

      address: :bro:type:`addr` :bro:attr:`&optional`

      octets: :bro:type:`string` :bro:attr:`&optional`

   A generic SNMP object value, that may include any of the
   valid ``ObjectSyntax`` values from :rfc:`1155` or :rfc:`3416`.
   The value is decoded whenever possible and assigned to
   the appropriate field, which can be determined from the value
   of the ``tag`` field.  For tags that can't be mapped to an
   appropriate type, the ``octets`` field holds the BER encoded
   ASN.1 content if there is any (though, ``octets`` is may also
   be used for other tags such as OCTET STRINGS or Opaque).  Null
   values will only have their corresponding tag value set.

.. bro:type:: SNMP::Binding

   :Type: :bro:type:`record`

      oid: :bro:type:`string`

      value: :bro:type:`SNMP::ObjectValue`

   The ``VarBind`` data structure from either :rfc:`1157` or
   :rfc:`3416`, which maps an Object Identifier to a value.

.. bro:type:: SNMP::Bindings

   :Type: :bro:type:`vector` of :bro:type:`SNMP::Binding`

   A ``VarBindList`` data structure from either :rfc:`1157` or :rfc:`3416`.
   A sequences of :bro:see:`SNMP::Binding`, which maps an OIDs to values.

Events
++++++

.. bro:id:: snmp_get_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``GetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_get_next_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``GetNextRequest-PDU`` message from either :rfc:`1157` or
   :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``GetResponse-PDU`` message from :rfc:`1157` or a
   ``Response-PDU`` from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_set_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``SetRequest-PDU`` message from either :rfc:`1157` or :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_trap

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::TrapPDU`)

   An SNMP ``Trap-PDU`` message from :rfc:`1157`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_get_bulk_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::BulkPDU`)

   An SNMP ``GetBulkRequest-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_inform_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``InformRequest-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_trapV2

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``SNMPv2-Trap-PDU`` message from :rfc:`1157`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_report

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, pdu: :bro:type:`SNMP::PDU`)

   An SNMP ``Report-PDU`` message from :rfc:`3416`.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :pdu: An SNMP PDU data structure.

.. bro:id:: snmp_unknown_pdu

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, tag: :bro:type:`count`)

   An SNMP PDU message of unknown type.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :tag: The tag of the unknown SNMP PDU.

.. bro:id:: snmp_unknown_scoped_pdu

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`, tag: :bro:type:`count`)

   An SNMPv3 ``ScopedPDUData`` of unknown type (neither plaintext or
   an encrypted PDU was in the datagram).
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.
   

   :tag: The tag of the unknown SNMP PDU scope.

.. bro:id:: snmp_encrypted_pdu

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, header: :bro:type:`SNMP::Header`)

   An SNMPv3 encrypted PDU message.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :header: SNMP version-dependent data that precedes PDU data in the top-level
           SNMP message structure.

.. bro:id:: snmp_unknown_header_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, version: :bro:type:`count`)

   A datagram with an unknown SNMP version.
   

   :c: The connection over which the SNMP datagram is sent.
   

   :is_orig: The endpoint which sent the SNMP datagram.
   

   :version: The value of the unknown SNMP version.

Bro::SOCKS
----------

SOCKS analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_SOCKS`

Events
++++++

.. bro:id:: socks_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, request_type: :bro:type:`count`, sa: :bro:type:`SOCKS::Address`, p: :bro:type:`port`, user: :bro:type:`string`)

   Generated when a SOCKS request is analyzed.
   

   :c: The parent connection of the proxy.
   

   :version: The version of SOCKS this message used.
   

   :request_type: The type of the request.
   

   :sa: Address that the tunneled traffic should be sent to.
   

   :p: The destination port for the proxied traffic.
   

   :user: Username given for the SOCKS connection.  This is not yet implemented
         for SOCKSv5.

.. bro:id:: socks_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, reply: :bro:type:`count`, sa: :bro:type:`SOCKS::Address`, p: :bro:type:`port`)

   Generated when a SOCKS reply is analyzed.
   

   :c: The parent connection of the proxy.
   

   :version: The version of SOCKS this message used.
   

   :reply: The status reply from the server.
   

   :sa: The address that the server sent the traffic to.
   

   :p: The destination port for the proxied traffic.

.. bro:id:: socks_login_userpass_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated when a SOCKS client performs username and password based login.
   

   :c: The parent connection of the proxy.
   

   :user: The given username.
   

   :password: The given password.

.. bro:id:: socks_login_userpass_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, code: :bro:type:`count`)

   Generated when a SOCKS server replies to a username/password login attempt.
   

   :c: The parent connection of the proxy.
   

   :code: The response code for the attempted login.

Bro::SSH
--------

Secure Shell analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_SSH`

Types
+++++

.. bro:type:: SSH::Algorithm_Prefs

   :Type: :bro:type:`record`

      client_to_server: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         The algorithm preferences for client to server communication

      server_to_client: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional`
         The algorithm preferences for server to client communication

   The client and server each have some preferences for the algorithms used
   in each direction.

.. bro:type:: SSH::Capabilities

   :Type: :bro:type:`record`

      kex_algorithms: :bro:type:`string_vec`
         Key exchange algorithms

      server_host_key_algorithms: :bro:type:`string_vec`
         The algorithms supported for the server host key

      encryption_algorithms: :bro:type:`SSH::Algorithm_Prefs`
         Symmetric encryption algorithm preferences

      mac_algorithms: :bro:type:`SSH::Algorithm_Prefs`
         Symmetric MAC algorithm preferences

      compression_algorithms: :bro:type:`SSH::Algorithm_Prefs`
         Compression algorithm preferences

      languages: :bro:type:`SSH::Algorithm_Prefs` :bro:attr:`&optional`
         Language preferences

      is_server: :bro:type:`bool`
         Are these the capabilities of the server?

   This record lists the preferences of an SSH endpoint for
   algorithm selection. During the initial :abbr:`SSH (Secure Shell)`
   key exchange, each endpoint lists the algorithms
   that it supports, in order of preference. See
   :rfc:`4253#section-7.1` for details.

Events
++++++

.. bro:id:: ssh_server_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`)

   An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
   from the server. This contains an identification string that's used
   for version identification. See :rfc:`4253#section-4.2` for
   details.
   

   :c: The connection over which the message was sent.
   

   :version: The identification string
   
   .. bro:see:: ssh_client_version ssh_auth_successful ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key

.. bro:id:: ssh_client_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`string`)

   An :abbr:`SSH (Secure Shell)` Protocol Version Exchange message
   from the client. This contains an identification string that's used
   for version identification. See :rfc:`4253#section-4.2` for
   details.
   

   :c: The connection over which the message was sent.
   

   :version: The identification string
   
   .. bro:see:: ssh_server_version ssh_auth_successful ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key

.. bro:id:: ssh_auth_successful

   :Type: :bro:type:`event` (c: :bro:type:`connection`, auth_method_none: :bro:type:`bool`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had a successful
   authentication. This determination is based on packet size
   analysis, and errs on the side of caution - that is, if there's any
   doubt about the authentication success, this event is *not* raised.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :auth_method_none: This is true if the analyzer detected a
      successful connection before any authentication challenge. The
      :abbr:`SSH (Secure Shell)` protocol provides a mechanism for
      unauthenticated access, which some servers support.
   
   .. bro:see:: ssh_server_version ssh_client_version ssh_auth_failed
      ssh_auth_result ssh_auth_attempted ssh_capabilities
      ssh2_server_host_key ssh1_server_host_key ssh_server_host_key
      ssh_encrypted_packet ssh2_dh_server_params ssh2_gss_error
      ssh2_ecc_key

.. bro:id:: ssh_auth_attempted

   :Type: :bro:type:`event` (c: :bro:type:`connection`, authenticated: :bro:type:`bool`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   connection was determined to have had an authentication attempt.
   This determination is based on packet size analysis, and errs
   on the side of caution - that is, if there's any doubt about
   whether or not an authenication attempt occured, this event is
   *not* raised.
   
   At this point in the protocol, all we can determine is whether
   or not the user is authenticated. We don't know if the particular
   attempt succeeded or failed, since some servers require multiple
   authentications (e.g. require both a password AND a pubkey), and
   could return an authentication failed message which is marked
   as a partial success.
   
   This event will often be raised multiple times per connection.
   In almost all connections, it will be raised once unless
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :authenticated: This is true if the analyzer detected a
      successful connection from the authentication attempt.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_capabilities ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_capabilities

   :Type: :bro:type:`event` (c: :bro:type:`connection`, cookie: :bro:type:`string`, capabilities: :bro:type:`SSH::Capabilities`)

   During the initial :abbr:`SSH (Secure Shell)` key exchange, each
   endpoint lists the algorithms that it supports, in order of
   preference. This event is generated for each endpoint, when the
   SSH_MSG_KEXINIT message is seen. See :rfc:`4253#section-7.1` for
   details.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :cookie: The SSH_MSG_KEXINIT cookie - a random value generated by
      the sender.
   

   :capabilities: The list of algorithms and languages that the sender
      advertises support for, in order of preference.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh2_server_host_key ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh2_server_host_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, key: :bro:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH2.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :key: The server's public host key. Note that this is the public key
      itself, and not just the fingerprint or hash.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh1_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh1_server_host_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, p: :bro:type:`string`, e: :bro:type:`string`)

   During the :abbr:`SSH (Secure Shell)` key exchange, the server
   supplies its public host key. This event is generated when the
   appropriate key exchange message is seen for SSH1.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :p: The prime for the server's public host key.
   

   :e: The exponent for the serer's public host key.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh_server_host_key ssh_encrypted_packet ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh_encrypted_packet

   :Type: :bro:type:`event` (c: :bro:type:`connection`, orig: :bro:type:`bool`, len: :bro:type:`count`)

   This event is generated when an :abbr:`SSH (Secure Shell)`
   encrypted packet is seen. This event is not handled by default, but
   is provided for heuristic analysis scripts. Note that you have to set
   :bro:id:`SSH::disable_analyzer_after_detection` to false to use this
   event. This carries a performance penalty.
   

   :c: The connection over which the :abbr:`SSH (Secure Shell)`
      connection took place.
   

   :orig: Whether the packet was sent by the originator of the TCP
      connection.
   

   :len: The length of the :abbr:`SSH (Secure Shell)` payload, in
      bytes. Note that this ignores reassembly, as this is unknown.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh2_dh_server_params
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh2_dh_server_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, p: :bro:type:`string`, q: :bro:type:`string`)

   Generated if the connection uses a Diffie-Hellman Group Exchange
   key exchange method. This event contains the server DH parameters,
   which are sent in the SSH_MSG_KEY_DH_GEX_GROUP message as defined in
   :rfc:`4419#section-3`.
   

   :c: The connection.
   

   :p: The DH prime modulus.
   

   :q: The DH generator.
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh_encrypted_packet
      ssh2_gss_error ssh2_ecc_key

.. bro:id:: ssh2_gss_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, major_status: :bro:type:`count`, minor_status: :bro:type:`count`, err_msg: :bro:type:`string`)

   In the event of a GSS-API error on the server, the server MAY send
   send an error message with some additional details. This event is
   generated when such an error message is seen. For more information,
   see :rfc:`4462#section-2.1`.
   

   :c: The connection.
   

   :major_status: GSS-API major status code.
   

   :minor_status: GSS-API minor status code.
   

   :err_msg: Detailed human-readable error message
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh_encrypted_packet
      ssh2_dh_server_params ssh2_ecc_key

.. bro:id:: ssh2_ecc_key

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, q: :bro:type:`string`)

   The :abbr:`ECDH (Elliptic Curve Diffie-Hellman)` and
   :abbr:`ECMQV (Elliptic Curve Menezes-Qu-Vanstone)` key exchange
   algorithms use two ephemeral key pairs to generate a shared
   secret. This event is generated when either the client's or
   server's ephemeral public key is seen. For more information, see:
   :rfc:`5656#section-4`.
   

   :c: The connection
   

   :is_orig: Did this message come from the originator?
   

   :q: The ephemeral public key
   
   .. bro:see:: ssh_server_version ssh_client_version
      ssh_auth_successful ssh_auth_failed ssh_auth_result
      ssh_auth_attempted ssh_capabilities ssh2_server_host_key
      ssh1_server_host_key ssh_server_host_key ssh_encrypted_packet
      ssh2_dh_server_params ssh2_gss_error

Bro::SSL
--------

SSL/TLS and DTLS analyzers

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_DTLS`

:bro:enum:`Analyzer::ANALYZER_SSL`

Options/Constants
+++++++++++++++++

.. bro:id:: SSL::dtls_max_version_errors

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10``

   Number of non-DTLS frames that can occur in a DTLS connection before
   parsing of the connection is suspended.
   DTLS does not immediately stop parsing a connection because other protocols
   might be interleaved in the same UDP "connection".

.. bro:id:: SSL::dtls_max_reported_version_errors

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1``

   Maximum number of invalid version errors to report in one DTLS connection.

Types
+++++

.. bro:type:: SSL::SignatureAndHashAlgorithm

   :Type: :bro:type:`record`

      HashAlgorithm: :bro:type:`count`
         Hash algorithm number

      SignatureAlgorithm: :bro:type:`count`
         Signature algorithm number


Events
++++++

.. bro:id:: ssl_client_hello

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, record_version: :bro:type:`count`, possible_ts: :bro:type:`time`, client_random: :bro:type:`string`, session_id: :bro:type:`string`, ciphers: :bro:type:`index_vec`, comp_methods: :bro:type:`index_vec`)

   Generated for an SSL/TLS client's initial *hello* message.  SSL/TLS sessions
   start with an unencrypted handshake, and Bro extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :version: The protocol version as extracted from the client's message.  The
            values are standardized as part of the SSL/TLS protocol. The
            :bro:id:`SSL::version_strings` table maps them to descriptive names.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :possible_ts: The current time as sent by the client. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care.
   

   :session_id: The session ID sent by the client (if any).
   

   :client_random: The random value sent by the client. For version 2 connections,
   		  the client challenge is returned.
   

   :ciphers: The list of ciphers the client offered to use. The values are
            standardized as part of the SSL/TLS protocol. The
            :bro:id:`SSL::cipher_desc` table maps them to descriptive names.
   

   :comp_methods: The list of compression methods that the client offered to use.
                 This value is not sent in TLSv1.3 or SSLv2.
   
   .. bro:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_handshake_message
      ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. bro:id:: ssl_server_hello

   :Type: :bro:type:`event` (c: :bro:type:`connection`, version: :bro:type:`count`, record_version: :bro:type:`count`, possible_ts: :bro:type:`time`, server_random: :bro:type:`string`, session_id: :bro:type:`string`, cipher: :bro:type:`count`, comp_method: :bro:type:`count`)

   Generated for an SSL/TLS server's initial *hello* message. SSL/TLS sessions
   start with an unencrypted handshake, and Bro extracts as much information out
   of that as it can. This event provides access to the initial information
   sent by the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :version: The protocol version as extracted from the server's message.
            The values are standardized as part of the SSL/TLS protocol. The
            :bro:id:`SSL::version_strings` table maps them to descriptive names.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :possible_ts: The current time as sent by the server. Note that SSL/TLS does
                not require clocks to be set correctly, so treat with care. This value
                is not sent in TLSv1.3.
   

   :session_id: The session ID as sent back by the server (if any). This value is not
               sent in TLSv1.3.
   

   :server_random: The random value sent by the server. For version 2 connections,
   		  the connection-id is returned.
   

   :cipher: The cipher chosen by the server.  The values are standardized as part
           of the SSL/TLS protocol. The :bro:id:`SSL::cipher_desc` table maps
           them to descriptive names.
   

   :comp_method: The compression method chosen by the client. The values are
                standardized as part of the SSL/TLS protocol. This value is not
                sent in TLSv1.3 or SSLv2.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_extension
      ssl_session_ticket_handshake x509_certificate ssl_server_curve
      ssl_dh_server_params ssl_handshake_message ssl_change_cipher_spec
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. bro:id:: ssl_extension

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, code: :bro:type:`count`, val: :bro:type:`string`)

   Generated for SSL/TLS extensions seen in an initial handshake.  SSL/TLS
   sessions start with an unencrypted handshake, and Bro extracts as much
   information out of that as it can. This event provides access to any
   extensions either side sends as part of an extended *hello* message.
   
   Note that Bro offers more specialized events for a few extensions.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :code: The numerical code of the extension.  The values are standardized as
         part of the SSL/TLS protocol. The :bro:id:`SSL::extensions` table maps
         them to descriptive names.
   

   :val: The raw extension value that was sent in the message.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension_ec_point_formats
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_signature_algorithm ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions

.. bro:id:: ssl_extension_elliptic_curves

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, curves: :bro:type:`index_vec`)

   Generated for an SSL/TLS Elliptic Curves extension. This TLS extension is
   defined in :rfc:`4492` and sent by the client in the initial handshake. It
   gives the list of elliptic curves supported by the client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :curves: List of supported elliptic curves.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_ec_point_formats ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve ssl_extension_signature_algorithm
      ssl_extension_key_share ssl_rsa_client_pms ssl_server_signature
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. bro:id:: ssl_extension_ec_point_formats

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, point_formats: :bro:type:`index_vec`)

   Generated for an SSL/TLS Supported Point Formats extension. This TLS extension
   is defined in :rfc:`4492` and sent by the client and/or server in the initial
   handshake. It gives the list of elliptic curve point formats supported by the
   client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :point_formats: List of supported point formats.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve ssl_extension_signature_algorithm
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_extension_signature_algorithm

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, signature_algorithms: :bro:type:`signature_and_hashalgorithm_vec`)

   Generated for an Signature Algorithms extension. This TLS extension
   is defined in :rfc:`5246` and sent by the client in the initial
   handshake. It gives the list of signature and hash algorithms supported by the
   client.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :signature_algorithms: List of supported signature and hash algorithm pairs.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_extension_key_share

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, curves: :bro:type:`index_vec`)

   Generated for a Key Share extension. This TLS extension is defined in TLS1.3-draft16
   and sent by the client and the server in the initial handshake. It gives the list of
   named groups supported by the client and chosen by the server.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :curves: List of supported/chosen named groups.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_server_curve
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_server_curve

   :Type: :bro:type:`event` (c: :bro:type:`connection`, curve: :bro:type:`count`)
   :Attributes: :bro:attr:`&deprecated`

   Generated if a named curve is chosen by the server for an SSL/TLS connection.
   The curve is sent by the server in the ServerKeyExchange message as defined
   in :rfc:`4492`, in case an ECDH or ECDHE cipher suite is chosen.
   

   :c: The connection.
   

   :curve: The curve.
   
   .. note:: This event is deprecated and superseded by the ssl_ecdh_server_params
             event. This event will be removed in a future version of Bro.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_application_layer_protocol_negotiation
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms ssl_server_signature

.. bro:id:: ssl_ecdh_server_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, curve: :bro:type:`count`, point: :bro:type:`string`)

   Generated if a server uses an ECDH-anon or ECDHE cipher suite using a named curve
   This event contains the named curve name and the server ECDH parameters contained
   in the ServerKeyExchange message as defined in :rfc:`4492`.
   

   :c: The connection.
   

   :curve: The curve parameters.
   

   :point: The server's ECDH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_client_params ssl_rsa_client_pms

.. bro:id:: ssl_dh_server_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, p: :bro:type:`string`, q: :bro:type:`string`, Ys: :bro:type:`string`)

   Generated if a server uses a DH-anon or DHE cipher suite. This event contains
   the server DH parameters, contained in the ServerKeyExchange message as
   defined in :rfc:`5246`.
   

   :c: The connection.
   

   :p: The DH prime modulus.
   

   :q: The DH generator.
   

   :Ys: The server's DH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params
      ssl_rsa_client_pms

.. bro:id:: ssl_server_signature

   :Type: :bro:type:`event` (c: :bro:type:`connection`, signature_and_hashalgorithm: :bro:type:`SSL::SignatureAndHashAlgorithm`, signature: :bro:type:`string`)

   Generated if a server uses a non-anonymous DHE or ECDHE cipher suite. This event
   contains the server signature over the key exchange parameters contained in
   the ServerKeyExchange message as defined in :rfc:`4492` and :rfc:`5246`.
   

   :c: The connection.
   

   :signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct. This field is only present
                                starting with TLSv1.2 and DTLSv1.2. Earlier versions
                                used a hardcoded hash algorithm. For protocol versions
                                below D(TLS)v1.2 this field is filled with an dummy
                                value of 256.
   

   :signature: Signature part of the digitally_signed struct. The private key
              corresponding to the certified public key in the server's certificate
              message is used for signing.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_rsa_client_pms
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. bro:id:: ssl_ecdh_client_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, point: :bro:type:`string`)

   Generated if a client uses an ECDH-anon or ECDHE cipher suite. This event
   contains the client ECDH public value contained in the ClientKeyExchange
   message as defined in :rfc:`4492`.
   

   :c: The connection.
   

   :point: The client's ECDH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_rsa_client_pms

.. bro:id:: ssl_dh_client_params

   :Type: :bro:type:`event` (c: :bro:type:`connection`, Yc: :bro:type:`string`)

   Generated if a client uses a DH-anon or DHE cipher suite. This event contains
   the client DH parameters contained in the ClientKeyExchange message as
   defined in :rfc:`5246`.
   

   :c: The connection.
   

   :Yc: The client's DH public key.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_ecdh_server_params ssl_ecdh_client_params ssl_rsa_client_pms

.. bro:id:: ssl_rsa_client_pms

   :Type: :bro:type:`event` (c: :bro:type:`connection`, pms: :bro:type:`string`)

   Generated if a client uses RSA key exchange. This event contains the client
   encrypted pre-master secret which is encrypted using the public key of the
   server's certificate as defined in :rfc:`5246`.
   

   :c: The connection.
   

   :pms: The encrypted pre-master secret.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_server_curve ssl_server_signature
      ssl_dh_client_params ssl_ecdh_server_params ssl_ecdh_client_params

.. bro:id:: ssl_extension_application_layer_protocol_negotiation

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, protocols: :bro:type:`string_vec`)

   Generated for an SSL/TLS Application-Layer Protocol Negotiation extension.
   This TLS extension is defined in draft-ietf-tls-applayerprotoneg and sent in
   the initial handshake. It contains the list of client supported application
   protocols by the client or the server, respectively.
   
   At the moment it is mostly used to negotiate the use of SPDY / HTTP2.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :protocols: List of supported application layer protocols.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_extension_server_name

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, names: :bro:type:`string_vec`)

   Generated for an SSL/TLS Server Name extension. This SSL/TLS extension is
   defined in :rfc:`3546` and sent by the client in the initial handshake. It
   contains the name of the server it is contacting. This information can be
   used by the server to choose the correct certificate for the host the client
   wants to contact.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :names: A list of server names (DNS hostnames).
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_extension_signed_certificate_timestamp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, version: :bro:type:`count`, logid: :bro:type:`string`, timestamp: :bro:type:`count`, signature_and_hashalgorithm: :bro:type:`SSL::SignatureAndHashAlgorithm`, signature: :bro:type:`string`)

   Generated for the signed_certificate_timestamp TLS extension as defined in
   :rfc:`6962`. The extension is used to transmit signed proofs that are
   used for Certificate Transparency.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :version: the version of the protocol to which the SCT conforms. Always
            should be 0 (representing version 1)
   

   :logid: 32 bit key id
   

   :timestamp: the NTP Time when the entry was logged measured since
              the epoch, ignoring leap seconds, in milliseconds.
   

   :signature_and_hashalgorithm: signature and hash algorithm used for the
                                digitally_signed struct
   

   :signature: signature part of the digitally_signed struct
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_server_name ssl_extension_key_share
      ssl_extension_psk_key_exchange_modes ssl_extension_supported_versions
      ssl_extension_application_layer_protocol_negotiation
      x509_ocsp_ext_signed_certificate_timestamp sct_verify

.. bro:id:: ssl_extension_supported_versions

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, versions: :bro:type:`index_vec`)

   Generated for an TLS Supported Versions extension. This TLS extension
   is defined in the TLS 1.3 rfc and sent by the client in the initial handshake.
   It contains the TLS versions that it supports. This informaion can be used by
   the server to choose the best TLS version o use.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :versions: List of supported TLS versions.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_psk_key_exchange_modes ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_extension_psk_key_exchange_modes

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, modes: :bro:type:`index_vec`)

   Generated for an TLS Pre-Shared Key Exchange Modes extension. This TLS extension is defined
   in the TLS 1.3 rfc and sent by the client in the initial handshake. It contains the
   list of Pre-Shared Key Exchange Modes that it supports.

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :versions: List of supported Pre-Shared Key Exchange Modes.
   
   .. bro:see:: ssl_alert ssl_client_hello ssl_established ssl_server_hello
      ssl_session_ticket_handshake ssl_extension
      ssl_extension_elliptic_curves ssl_extension_ec_point_formats
      ssl_extension_application_layer_protocol_negotiation
      ssl_extension_key_share ssl_extension_server_name
      ssl_extension_supported_versions ssl_extension_signed_certificate_timestamp

.. bro:id:: ssl_established

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated at the end of an SSL/TLS handshake. SSL/TLS sessions start with
   an unencrypted handshake, and Bro extracts as much information out of that
   as it can. This event signals the time when an SSL/TLS has finished the
   handshake and its endpoints consider it as fully established. Typically,
   everything from now on will be encrypted.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   
   .. bro:see:: ssl_alert ssl_client_hello  ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate

.. bro:id:: ssl_alert

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, level: :bro:type:`count`, desc: :bro:type:`count`)

   Generated for SSL/TLS alert records. SSL/TLS sessions start with an
   unencrypted handshake, and Bro extracts as much information out of that as
   it can. If during that handshake, an endpoint encounters a fatal error, it
   sends an *alert* record, that in turn triggers this event. After an *alert*,
   any endpoint may close the connection immediately.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :level: The severity level, as sent in the *alert*. The values are defined as
          part of the SSL/TLS protocol.
   

   :desc: A numerical value identifying the cause of the *alert*. The values are
         defined as part of the SSL/TLS protocol.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake

.. bro:id:: ssl_session_ticket_handshake

   :Type: :bro:type:`event` (c: :bro:type:`connection`, ticket_lifetime_hint: :bro:type:`count`, ticket: :bro:type:`string`)

   Generated for SSL/TLS handshake messages that are a part of the
   stateless-server session resumption mechanism. SSL/TLS sessions start with
   an unencrypted handshake, and Bro extracts as much information out of that
   as it can. This event is raised when an SSL/TLS server passes a session
   ticket to the client that can later be used for resuming the session. The
   mechanism is described in :rfc:`4507`.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Transport_Layer_Security>`__ for
   more information about the SSL/TLS protocol.
   

   :c: The connection.
   

   :ticket_lifetime_hint: A hint from the server about how long the ticket
                         should be stored by the client.
   

   :ticket: The raw ticket data.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert

.. bro:id:: ssl_heartbeat

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, length: :bro:type:`count`, heartbeat_type: :bro:type:`count`, payload_length: :bro:type:`count`, payload: :bro:type:`string`)

   Generated for SSL/TLS heartbeat messages that are sent before session
   encryption starts. Generally heartbeat messages should rarely be seen in
   normal TLS traffic. Heartbeats are described in :rfc:`6520`.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :length: length of the entire heartbeat message.
   

   :heartbeat_type: type of the heartbeat message. Per RFC, 1 = request, 2 = response.
   

   :payload_length: length of the payload of the heartbeat message, according to
                   packet field.
   

   :payload: payload contained in the heartbeat message. Size can differ from
            payload_length, if payload_length and actual packet length disagree.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_encrypted_data

.. bro:id:: ssl_plaintext_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, record_version: :bro:type:`count`, content_type: :bro:type:`count`, length: :bro:type:`count`)

   Generated for SSL/TLS messages that are sent before full session encryption
   starts. Note that "full encryption" is a bit fuzzy, especially for TLSv1.3;
   here this event will be raised for early packets that are already using
   pre-encryption.  # This event is also used by Bro internally to determine if
   the connection has been completely setup. This is necessary as TLS 1.3 does
   not have CCS anymore.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :length: length of the entire message.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. bro:id:: ssl_encrypted_data

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, record_version: :bro:type:`count`, content_type: :bro:type:`count`, length: :bro:type:`count`)

   Generated for SSL/TLS messages that are sent after session encryption
   started.
   
   Note that :bro:id:`SSL::disable_analyzer_after_detection` has to be changed
   from its default to false for this event to be generated.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :record_version: TLS version given in the record layer of the message.
                   Set to 0 for SSLv2.
   

   :content_type: message type as reported by TLS session layer. Not populated for
                 SSLv2.
   

   :length: length of the entire message.
   
   .. bro:see::  ssl_client_hello ssl_established ssl_extension ssl_server_hello
      ssl_alert ssl_heartbeat

.. bro:id:: ssl_stapled_ocsp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, response: :bro:type:`string`)

   This event contains the OCSP response contained in a Certificate Status Request
   message, when the client requested OCSP stapling and the server supports it.
   See description in :rfc:`6066`.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :response: OCSP data.

.. bro:id:: ssl_handshake_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg_type: :bro:type:`count`, length: :bro:type:`count`)

   This event is raised for each unencrypted SSL/TLS handshake message.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   

   :msg_type: Type of the handshake message that was seen.
   

   :length: Length of the handshake message that was seen.
   
   .. bro:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_change_cipher_spec

.. bro:id:: ssl_change_cipher_spec

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   This event is raised when a SSL/TLS ChangeCipherSpec message is encountered
   before encryption begins. Traffic will be encrypted following this message.
   

   :c: The connection.
   

   :is_orig: True if event is raised for originator side of the connection.
   
   .. bro:see:: ssl_alert ssl_established ssl_extension ssl_server_hello
      ssl_session_ticket_handshake x509_certificate ssl_client_hello
      ssl_handshake_message

Functions
+++++++++

.. bro:id:: set_ssl_established

   :Type: :bro:type:`function` (c: :bro:type:`connection`) : :bro:type:`any`

   Sets if the SSL analyzer should consider the connection established (handshake
   finished succesfully).
   

   :c: The SSL connection.

Bro::SteppingStone
------------------

Stepping stone analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_STEPPINGSTONE`

Events
++++++

.. bro:id:: stp_create_endp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, e: :bro:type:`int`, is_orig: :bro:type:`bool`)

   Deprecated. Will be removed.

.. bro:id:: stp_resume_endp

   :Type: :bro:type:`event` (e: :bro:type:`int`)

   Event internal to the stepping stone detector.

.. bro:id:: stp_correlate_pair

   :Type: :bro:type:`event` (e1: :bro:type:`int`, e2: :bro:type:`int`)

   Event internal to the stepping stone detector.

.. bro:id:: stp_remove_pair

   :Type: :bro:type:`event` (e1: :bro:type:`int`, e2: :bro:type:`int`)

   Event internal to the stepping stone detector.

.. bro:id:: stp_remove_endp

   :Type: :bro:type:`event` (e: :bro:type:`int`)

   Event internal to the stepping stone detector.

Bro::Syslog
-----------

Syslog analyzer UDP-only

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_SYSLOG`

Events
++++++

.. bro:id:: syslog_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, facility: :bro:type:`count`, severity: :bro:type:`count`, msg: :bro:type:`string`)

   Generated for monitored Syslog messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Syslog>`__ for more
   information about the Syslog protocol.
   

   :c: The connection record for the underlying transport-layer session/flow.
   

   :facility: The "facility" included in the message.
   

   :severity: The "severity" included in the message.
   

   :msg: The message logged.
   
   .. note:: Bro currently parses only UDP syslog traffic. Support for TCP
      syslog will be added soon.

Bro::TCP
--------

TCP analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_CONTENTLINE`

:bro:enum:`Analyzer::ANALYZER_CONTENTS`

:bro:enum:`Analyzer::ANALYZER_TCP`

:bro:enum:`Analyzer::ANALYZER_TCPSTATS`

Events
++++++

.. bro:id:: new_connection_contents

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when reassembly starts for a TCP connection. This event is raised
   at the moment when Bro's TCP analyzer enables stream reassembly for a
   connection.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected connection_reset connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection partial_connection

.. bro:id:: connection_attempt

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for an unsuccessful connection attempt. This event is raised when
   an originator unsuccessfully attempted to establish a connection.
   "Unsuccessful" is defined as at least :bro:id:`tcp_attempt_delay` seconds
   having elapsed since the originator first sent a connection establishment
   packet to the destination without seeing a reply.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_established
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. bro:id:: connection_established

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when seeing a SYN-ACK packet from the responder in a TCP
   handshake.  An associated SYN packet was not seen from the originator
   side if its state is not set to :bro:see:`TCP_ESTABLISHED`.
   The final ACK of the handshake in response to SYN-ACK may
   or may not occur later, one way to tell is to check the *history* field of
   :bro:type:`connection` to see if the originator sent an ACK, indicated by
   'A' in the history string.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. bro:id:: partial_connection

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for a new active TCP connection if Bro did not see the initial
   handshake. This event is raised when Bro has observed traffic from each
   endpoint, but the activity did not begin with the usual connection
   establishment.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected connection_reset connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection new_connection_contents
   

.. bro:id:: connection_partial_close

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a previously inactive endpoint attempts to close a TCP
   connection via a normal FIN handshake or an abort RST sequence. When the
   endpoint sent one of these packets, Bro waits
   :bro:id:`tcp_partial_close_delay` prior to generating the event, to give
   the other endpoint a chance to close the connection normally.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. bro:id:: connection_finished

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for a TCP connection that finished normally. The event is raised
   when a regular FIN handshake from both endpoints was observed.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. bro:id:: connection_half_finished

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when one endpoint of a TCP connection attempted to gracefully close
   the connection, but the other endpoint is in the TCP_INACTIVE state. This can
   happen due to split routing, in which Bro only sees one side of a connection.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK  connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. bro:id:: connection_rejected

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for a rejected TCP connection. This event is raised when an
   originator attempted to setup a TCP connection but the responder replied
   with a RST packet denying it.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending  connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      If the responder does not respond at all, :bro:id:`connection_attempt` is
      raised instead. If the responder initially accepts the connection but
      aborts it later, Bro first generates :bro:id:`connection_established`
      and then :bro:id:`connection_reset`.

.. bro:id:: connection_reset

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when an endpoint aborted a TCP connection. The event is raised
   when one endpoint of an established TCP connection aborted by sending a RST
   packet.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_pending connection_rejected  connection_reused
      connection_state_remove connection_status_update connection_timeout
      scheduled_analyzer_applied new_connection new_connection_contents
      partial_connection

.. bro:id:: connection_pending

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for each still-open TCP connection when Bro terminates.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_first_ACK connection_half_finished connection_partial_close
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection zeek_done

.. bro:id:: connection_SYN_packet

   :Type: :bro:type:`event` (c: :bro:type:`connection`, pkt: :bro:type:`SYN_packet`)

   Generated for a SYN packet. Bro raises this event for every SYN packet seen
   by its TCP analyzer.
   

   :c: The connection.
   

   :pkt: Information extracted from the SYN packet.
   
   .. bro:see:: connection_EOF  connection_attempt connection_established
      connection_external connection_finished connection_first_ACK
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

.. bro:id:: connection_first_ACK

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated for the first ACK packet seen for a TCP connection from
   its *originator*.
   

   :c: The connection.
   
   .. bro:see:: connection_EOF connection_SYN_packet connection_attempt
      connection_established connection_external connection_finished
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection
   
   .. note::
   
      This event has quite low-level semantics and should be used only rarely.

.. bro:id:: connection_EOF

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated at the end of reassembled TCP connections. The TCP reassembler
   raised the event once for each endpoint of a connection when it finished
   reassembling the corresponding side of the communication.
   

   :c: The connection.
   

   :is_orig: True if the event is raised for the originator side.
   
   .. bro:see::  connection_SYN_packet connection_attempt connection_established
      connection_external connection_finished connection_first_ACK
      connection_half_finished connection_partial_close connection_pending
      connection_rejected connection_reset connection_reused connection_state_remove
      connection_status_update connection_timeout scheduled_analyzer_applied
      new_connection new_connection_contents partial_connection

.. bro:id:: tcp_packet

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, flags: :bro:type:`string`, seq: :bro:type:`count`, ack: :bro:type:`count`, len: :bro:type:`count`, payload: :bro:type:`string`)

   Generated for every TCP packet. This is a very low-level and expensive event
   that should be avoided when at all possible. It's usually infeasible to
   handle when processing even medium volumes of traffic in real-time.  It's
   slightly better than :bro:id:`new_packet` because it affects only TCP, but
   not much. That said, if you work from a trace and want to do some
   packet-level analysis, it may come in handy.
   

   :c: The connection the packet is part of.
   

   :is_orig: True if the packet was sent by the connection's originator.
   

   :flags: A string with the packet's TCP flags. In the string, each character
          corresponds to one set flag, as follows: ``S`` -> SYN; ``F`` -> FIN;
          ``R`` -> RST; ``A`` -> ACK; ``P`` -> PUSH.
   

   :seq: The packet's relative TCP sequence number.
   

   :ack: If the ACK flag is set for the packet, the packet's relative ACK
        number, else zero.
   

   :len: The length of the TCP payload, as specified in the packet header.
   

   :payload: The raw TCP payload. Note that this may be shorter than *len* if
            the packet was not fully captured.
   
   .. bro:see:: new_packet packet_contents tcp_option tcp_contents tcp_rexmit

.. bro:id:: tcp_option

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, opt: :bro:type:`count`, optlen: :bro:type:`count`)

   Generated for each option found in a TCP header. Like many of the ``tcp_*``
   events, this is a very low-level event and potentially expensive as it may
   be raised very often.
   

   :c: The connection the packet is part of.
   

   :is_orig: True if the packet was sent by the connection's originator.
   

   :opt: The numerical option number, as found in the TCP header.
   

   :optlen: The length of the options value.
   
   .. bro:see:: tcp_packet tcp_contents tcp_rexmit
   
   .. note:: There is currently no way to get the actual option value, if any.

.. bro:id:: tcp_contents

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, seq: :bro:type:`count`, contents: :bro:type:`string`)

   Generated for each chunk of reassembled TCP payload. When content delivery is
   enabled for a TCP connection (via :bro:id:`tcp_content_delivery_ports_orig`,
   :bro:id:`tcp_content_delivery_ports_resp`,
   :bro:id:`tcp_content_deliver_all_orig`,
   :bro:id:`tcp_content_deliver_all_resp`), this event is raised for each chunk
   of in-order payload reconstructed from the packet stream. Note that this
   event is potentially expensive if many connections carry significant amounts
   of data as then all that data needs to be passed on to the scripting layer.
   

   :c: The connection the payload is part of.
   

   :is_orig: True if the packet was sent by the connection's originator.
   

   :seq: The sequence number corresponding to the first byte of the payload
        chunk.
   

   :contents: The raw payload, which will be non-empty.
   
   .. bro:see:: tcp_packet tcp_option tcp_rexmit
      tcp_content_delivery_ports_orig tcp_content_delivery_ports_resp
      tcp_content_deliver_all_resp tcp_content_deliver_all_orig
   
   .. note::
   
      The payload received by this event is the same that is also passed into
      application-layer protocol analyzers internally. Subsequent invocations of
      this event for the same connection receive non-overlapping in-order chunks
      of its TCP payload stream. It is however undefined what size each chunk
      has; while Bro passes the data on as soon as possible, specifics depend on
      network-level effects such as latency, acknowledgements, reordering, etc.

.. bro:id:: tcp_rexmit

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, seq: :bro:type:`count`, len: :bro:type:`count`, data_in_flight: :bro:type:`count`, window: :bro:type:`count`)

   TODO.

.. bro:id:: tcp_multiple_checksum_errors

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, threshold: :bro:type:`count`)

   Generated if a TCP flow crosses a checksum-error threshold, per
   'C'/'c' history reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. bro:see::  udp_multiple_checksum_errors
      tcp_multiple_zero_windows tcp_multiple_retransmissions

.. bro:id:: tcp_multiple_zero_windows

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, threshold: :bro:type:`count`)

   Generated if a TCP flow crosses a zero-window threshold, per
   'W'/'w' history reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. bro:see::  tcp_multiple_checksum_errors tcp_multiple_retransmissions

.. bro:id:: tcp_multiple_retransmissions

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, threshold: :bro:type:`count`)

   Generated if a TCP flow crosses a retransmission threshold, per
   'T'/'t' history reporting.
   

   :c: The connection record for the TCP connection.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. bro:see::  tcp_multiple_checksum_errors tcp_multiple_zero_windows

.. bro:id:: contents_file_write_failure

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`)

   Generated when failing to write contents of a TCP stream to a file.
   

   :c: The connection whose contents are being recorded.
   

   :is_orig: Which side of the connection encountered a failure to write.
   

   :msg: A reason or description for the failure.
   
   .. bro:see:: set_contents_file get_contents_file

Functions
+++++++++

.. bro:id:: get_orig_seq

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`) : :bro:type:`count`

   Get the originator sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's originator, or 0
            if *cid* does not point to an active TCP connection.
   
   .. bro:see:: get_resp_seq

.. bro:id:: get_resp_seq

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`) : :bro:type:`count`

   Get the responder sequence number of a TCP connection. Sequence numbers
   are absolute (i.e., they reflect the values seen directly in packet headers;
   they are not relative to the beginning of the connection).
   

   :cid: The connection ID.
   

   :returns: The highest sequence number sent by a connection's responder, or 0
            if *cid* does not point to an active TCP connection.
   
   .. bro:see:: get_orig_seq

.. bro:id:: set_contents_file

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, direction: :bro:type:`count`, f: :bro:type:`file`) : :bro:type:`bool`

   Associates a file handle with a connection for writing TCP byte stream
   contents.
   

   :cid: The connection ID.
   

   :direction: Controls what sides of the connection to record. The argument can
              take one of the four values:
   
              - ``CONTENTS_NONE``: Stop recording the connection's content.
              - ``CONTENTS_ORIG``: Record the data sent by the connection
                originator (often the client).
              - ``CONTENTS_RESP``: Record the data sent by the connection
                responder (often the server).
              - ``CONTENTS_BOTH``: Record the data sent in both directions.
                Results in the two directions being intermixed in the file,
                in the order the data was seen by Bro.
   

   :f: The file handle of the file to write the contents to.
   

   :returns: Returns false if *cid* does not point to an active connection, and
            true otherwise.
   
   .. note::
   
       The data recorded to the file reflects the byte stream, not the
       contents of individual packets. Reordering and duplicates are
       removed. If any data is missing, the recording stops at the
       missing data; this can happen, e.g., due to an
       :bro:id:`content_gap` event.
   
   .. bro:see:: get_contents_file set_record_packets contents_file_write_failure

.. bro:id:: get_contents_file

   :Type: :bro:type:`function` (cid: :bro:type:`conn_id`, direction: :bro:type:`count`) : :bro:type:`file`

   Returns the file handle of the contents file of a connection.
   

   :cid: The connection ID.
   

   :direction: Controls what sides of the connection to record. See
              :bro:id:`set_contents_file` for possible values.
   

   :returns: The :bro:type:`file` handle for the contents file of the
            connection identified by *cid*. If the connection exists
            but there is no contents file for *direction*, then the function
            generates an error and returns a file handle to ``stderr``.
   
   .. bro:see:: set_contents_file set_record_packets contents_file_write_failure

Bro::Teredo
-----------

Teredo analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_TEREDO`

Events
++++++

.. bro:id:: teredo_packet

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for any IPv6 packet encapsulated in a Teredo tunnel.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_authentication teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: teredo_authentication

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo authentication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_packet teredo_origin_indication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: teredo_origin_indication

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for IPv6 packets encapsulated in a Teredo tunnel that
   use the Teredo origin indication encapsulation method.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_packet teredo_authentication teredo_bubble
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

.. bro:id:: teredo_bubble

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`teredo_hdr`)

   Generated for Teredo bubble packets.  That is, IPv6 packets encapsulated
   in a Teredo tunnel that have a Next Header value of :bro:id:`IPPROTO_NONE`.
   See :rfc:`4380` for more information about the Teredo protocol.
   

   :outer: The Teredo tunnel connection.
   

   :inner: The Teredo-encapsulated IPv6 packet header and transport header.
   
   .. bro:see:: teredo_packet teredo_authentication teredo_origin_indication
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

Bro::UDP
--------

UDP Analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_UDP`

Events
++++++

.. bro:id:: udp_request

   :Type: :bro:type:`event` (u: :bro:type:`connection`)

   Generated for each packet sent by a UDP flow's originator. This a potentially
   expensive event due to the volume of UDP traffic and should be used with
   care.
   

   :u: The connection record for the corresponding UDP flow.
   
   .. bro:see:: udp_contents udp_reply  udp_session_done

.. bro:id:: udp_reply

   :Type: :bro:type:`event` (u: :bro:type:`connection`)

   Generated for each packet sent by a UDP flow's responder. This a potentially
   expensive event due to the volume of UDP traffic and should be used with
   care.
   

   :u: The connection record for the corresponding UDP flow.
   
   .. bro:see:: udp_contents  udp_request udp_session_done

.. bro:id:: udp_contents

   :Type: :bro:type:`event` (u: :bro:type:`connection`, is_orig: :bro:type:`bool`, contents: :bro:type:`string`)

   Generated for UDP packets to pass on their payload. As the number of UDP
   packets can be very large, this event is normally raised only for those on
   ports configured in :bro:id:`udp_content_delivery_ports_orig` (for packets
   sent by the flow's originator) or :bro:id:`udp_content_delivery_ports_resp`
   (for packets sent by the flow's responder). However, delivery can be enabled
   for all UDP request and reply packets by setting
   :bro:id:`udp_content_deliver_all_orig` or
   :bro:id:`udp_content_deliver_all_resp`, respectively. Note that this
   event is also raised for all matching UDP packets, including empty ones.
   

   :u: The connection record for the corresponding UDP flow.
   

   :is_orig: True if the event is raised for the originator side.
   

   :contents: TODO.
   
   .. bro:see::  udp_reply udp_request udp_session_done
      udp_content_deliver_all_orig udp_content_deliver_all_resp
      udp_content_delivery_ports_orig udp_content_delivery_ports_resp

.. bro:id:: udp_multiple_checksum_errors

   :Type: :bro:type:`event` (u: :bro:type:`connection`, is_orig: :bro:type:`bool`, threshold: :bro:type:`count`)

   Generated if a UDP flow crosses a checksum-error threshold, per
   'C'/'c' history reporting.
   

   :u: The connection record for the corresponding UDP flow.
   

   :is_orig: True if the event is raised for the originator side.
   

   :threshold: the threshold that was crossed
   
   .. bro:see::  udp_reply udp_request udp_session_done
      tcp_multiple_checksum_errors

Bro::VXLAN
----------

VXLAN analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_VXLAN`

Events
++++++

.. bro:id:: vxlan_packet

   :Type: :bro:type:`event` (outer: :bro:type:`connection`, inner: :bro:type:`pkt_hdr`, vni: :bro:type:`count`)

   Generated for any packet encapsulated in a VXLAN tunnel.
   See :rfc:`7348` for more information about the VXLAN protocol.
   

   :outer: The VXLAN tunnel connection.
   

   :inner: The VXLAN-encapsulated Ethernet packet header and transport header.
   

   :vni: VXLAN Network Identifier.
   
   .. note:: Since this event may be raised on a per-packet basis, handling
      it may become particularly expensive for real-time analysis.

Bro::XMPP
---------

XMPP analyzer (StartTLS only)

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_XMPP`

Events
++++++

.. bro:id:: xmpp_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated when a XMPP connection goes encrypted after a successful
   StartTLS exchange between the client and the server.
   

   :c: The connection.

Bro::ZIP
--------

Generic ZIP support analyzer

Components
++++++++++

:bro:enum:`Analyzer::ANALYZER_ZIP`

