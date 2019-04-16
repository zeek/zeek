:tocdepth: 3

base/bif/plugins/Bro_BitTorrent.events.bif.zeek
===============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== =====
:bro:id:`bittorrent_peer_bitfield`: :bro:type:`event`       TODO.
:bro:id:`bittorrent_peer_cancel`: :bro:type:`event`         TODO.
:bro:id:`bittorrent_peer_choke`: :bro:type:`event`          TODO.
:bro:id:`bittorrent_peer_handshake`: :bro:type:`event`      TODO.
:bro:id:`bittorrent_peer_have`: :bro:type:`event`           TODO.
:bro:id:`bittorrent_peer_interested`: :bro:type:`event`     TODO.
:bro:id:`bittorrent_peer_keep_alive`: :bro:type:`event`     TODO.
:bro:id:`bittorrent_peer_not_interested`: :bro:type:`event` TODO.
:bro:id:`bittorrent_peer_piece`: :bro:type:`event`          TODO.
:bro:id:`bittorrent_peer_port`: :bro:type:`event`           TODO.
:bro:id:`bittorrent_peer_request`: :bro:type:`event`        TODO.
:bro:id:`bittorrent_peer_unchoke`: :bro:type:`event`        TODO.
:bro:id:`bittorrent_peer_unknown`: :bro:type:`event`        TODO.
:bro:id:`bittorrent_peer_weird`: :bro:type:`event`          TODO.
:bro:id:`bt_tracker_request`: :bro:type:`event`             TODO.
:bro:id:`bt_tracker_response`: :bro:type:`event`            TODO.
:bro:id:`bt_tracker_response_not_ok`: :bro:type:`event`     TODO.
:bro:id:`bt_tracker_weird`: :bro:type:`event`               TODO.
=========================================================== =====


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
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


