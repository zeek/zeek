:tocdepth: 3

base/bif/plugins/Zeek_BitTorrent.events.bif.zeek
================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= =====
:zeek:id:`bittorrent_peer_bitfield`: :zeek:type:`event`       TODO.
:zeek:id:`bittorrent_peer_cancel`: :zeek:type:`event`         TODO.
:zeek:id:`bittorrent_peer_choke`: :zeek:type:`event`          TODO.
:zeek:id:`bittorrent_peer_handshake`: :zeek:type:`event`      TODO.
:zeek:id:`bittorrent_peer_have`: :zeek:type:`event`           TODO.
:zeek:id:`bittorrent_peer_interested`: :zeek:type:`event`     TODO.
:zeek:id:`bittorrent_peer_keep_alive`: :zeek:type:`event`     TODO.
:zeek:id:`bittorrent_peer_not_interested`: :zeek:type:`event` TODO.
:zeek:id:`bittorrent_peer_piece`: :zeek:type:`event`          TODO.
:zeek:id:`bittorrent_peer_port`: :zeek:type:`event`           TODO.
:zeek:id:`bittorrent_peer_request`: :zeek:type:`event`        TODO.
:zeek:id:`bittorrent_peer_unchoke`: :zeek:type:`event`        TODO.
:zeek:id:`bittorrent_peer_unknown`: :zeek:type:`event`        TODO.
:zeek:id:`bittorrent_peer_weird`: :zeek:type:`event`          TODO.
:zeek:id:`bt_tracker_request`: :zeek:type:`event`             TODO.
:zeek:id:`bt_tracker_response`: :zeek:type:`event`            TODO.
:zeek:id:`bt_tracker_response_not_ok`: :zeek:type:`event`     TODO.
:zeek:id:`bt_tracker_weird`: :zeek:type:`event`               TODO.
============================================================= =====


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
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


