:tocdepth: 3

policy/frameworks/packet-filter/shunt.zeek
==========================================
.. zeek:namespace:: PacketFilter


:Namespace: PacketFilter
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/packet-filter </scripts/base/frameworks/packet-filter/index>`

Summary
~~~~~~~
Redefinable Options
###################
=============================================================================== =======================================================================
:zeek:id:`PacketFilter::max_bpf_shunts`: :zeek:type:`count` :zeek:attr:`&redef` The maximum number of BPF based shunts that Zeek is allowed to perform.
=============================================================================== =======================================================================

Redefinitions
#############
============================================ ============================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`PacketFilter::Cannot_BPF_Shunt_Conn`:
                                               Limitations in BPF make shunting some connections with BPF
                                               impossible.
                                             
                                             * :zeek:enum:`PacketFilter::No_More_Conn_Shunts_Available`:
                                               Indicative that :zeek:id:`PacketFilter::max_bpf_shunts`
                                               connections are already being shunted with BPF filters and
                                               no more are allowed.
============================================ ============================================================

Functions
#########
========================================================================== ============================================================================
:zeek:id:`PacketFilter::current_shunted_conns`: :zeek:type:`function`      Retrieve the currently shunted connections.
:zeek:id:`PacketFilter::current_shunted_host_pairs`: :zeek:type:`function` Retrieve the currently shunted host pairs.
:zeek:id:`PacketFilter::force_unshunt_host_pair`: :zeek:type:`function`    Performs the same function as the :zeek:id:`PacketFilter::unshunt_host_pair`
                                                                           function, but it forces an immediate filter update.
:zeek:id:`PacketFilter::shunt_conn`: :zeek:type:`function`                 Call this function to use BPF to shunt a connection (to prevent the
                                                                           data packets from reaching Zeek).
:zeek:id:`PacketFilter::shunt_host_pair`: :zeek:type:`function`            This function will use a BPF expression to shunt traffic between
                                                                           the two hosts given in the `conn_id` so that the traffic is never
                                                                           exposed to Zeek's traffic processing.
:zeek:id:`PacketFilter::unshunt_host_pair`: :zeek:type:`function`          Remove shunting for a host pair given as a `conn_id`.
========================================================================== ============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. zeek:id:: PacketFilter::max_bpf_shunts
   :source-code: policy/frameworks/packet-filter/shunt.zeek 8 8

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   The maximum number of BPF based shunts that Zeek is allowed to perform.

Functions
#########
.. zeek:id:: PacketFilter::current_shunted_conns
   :source-code: policy/frameworks/packet-filter/shunt.zeek 86 89

   :Type: :zeek:type:`function` () : :zeek:type:`set` [:zeek:type:`conn_id`]

   Retrieve the currently shunted connections.

.. zeek:id:: PacketFilter::current_shunted_host_pairs
   :source-code: policy/frameworks/packet-filter/shunt.zeek 91 94

   :Type: :zeek:type:`function` () : :zeek:type:`set` [:zeek:type:`conn_id`]

   Retrieve the currently shunted host pairs.

.. zeek:id:: PacketFilter::force_unshunt_host_pair
   :source-code: policy/frameworks/packet-filter/shunt.zeek 133 142

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Performs the same function as the :zeek:id:`PacketFilter::unshunt_host_pair`
   function, but it forces an immediate filter update.

.. zeek:id:: PacketFilter::shunt_conn
   :source-code: policy/frameworks/packet-filter/shunt.zeek 144 162

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Call this function to use BPF to shunt a connection (to prevent the
   data packets from reaching Zeek).  For TCP connections, control
   packets are still allowed through so that Zeek can continue logging
   the connection and it can stop shunting once the connection ends.

.. zeek:id:: PacketFilter::shunt_host_pair
   :source-code: policy/frameworks/packet-filter/shunt.zeek 108 118

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`) : :zeek:type:`bool`

   This function will use a BPF expression to shunt traffic between
   the two hosts given in the `conn_id` so that the traffic is never
   exposed to Zeek's traffic processing.

.. zeek:id:: PacketFilter::unshunt_host_pair
   :source-code: policy/frameworks/packet-filter/shunt.zeek 120 131

   :Type: :zeek:type:`function` (id: :zeek:type:`conn_id`) : :zeek:type:`bool`

   Remove shunting for a host pair given as a `conn_id`.  The filter
   is not immediately removed.  It waits for the occasional filter
   update done by the `PacketFilter` framework.


