:tocdepth: 3

policy/frameworks/packet-filter/shunt.bro
=========================================
.. bro:namespace:: PacketFilter


:Namespace: PacketFilter
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/frameworks/packet-filter </scripts/base/frameworks/packet-filter/index>`

Summary
~~~~~~~
Redefinable Options
###################
============================================================================ ======================================================================
:bro:id:`PacketFilter::max_bpf_shunts`: :bro:type:`count` :bro:attr:`&redef` The maximum number of BPF based shunts that Bro is allowed to perform.
============================================================================ ======================================================================

Redefinitions
#############
========================================== =
:bro:type:`Notice::Type`: :bro:type:`enum` 
========================================== =

Functions
#########
======================================================================== ===========================================================================
:bro:id:`PacketFilter::current_shunted_conns`: :bro:type:`function`      Retrieve the currently shunted connections.
:bro:id:`PacketFilter::current_shunted_host_pairs`: :bro:type:`function` Retrieve the currently shunted host pairs.
:bro:id:`PacketFilter::force_unshunt_host_pair`: :bro:type:`function`    Performs the same function as the :bro:id:`PacketFilter::unshunt_host_pair`
                                                                         function, but it forces an immediate filter update.
:bro:id:`PacketFilter::shunt_conn`: :bro:type:`function`                 Call this function to use BPF to shunt a connection (to prevent the
                                                                         data packets from reaching Bro).
:bro:id:`PacketFilter::shunt_host_pair`: :bro:type:`function`            This function will use a BPF expression to shunt traffic between
                                                                         the two hosts given in the `conn_id` so that the traffic is never
                                                                         exposed to Bro's traffic processing.
:bro:id:`PacketFilter::unshunt_host_pair`: :bro:type:`function`          Remove shunting for a host pair given as a `conn_id`.
======================================================================== ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Redefinable Options
###################
.. bro:id:: PacketFilter::max_bpf_shunts

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``100``

   The maximum number of BPF based shunts that Bro is allowed to perform.

Functions
#########
.. bro:id:: PacketFilter::current_shunted_conns

   :Type: :bro:type:`function` () : :bro:type:`set` [:bro:type:`conn_id`]

   Retrieve the currently shunted connections.

.. bro:id:: PacketFilter::current_shunted_host_pairs

   :Type: :bro:type:`function` () : :bro:type:`set` [:bro:type:`conn_id`]

   Retrieve the currently shunted host pairs.

.. bro:id:: PacketFilter::force_unshunt_host_pair

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`) : :bro:type:`bool`

   Performs the same function as the :bro:id:`PacketFilter::unshunt_host_pair`
   function, but it forces an immediate filter update.

.. bro:id:: PacketFilter::shunt_conn

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`) : :bro:type:`bool`

   Call this function to use BPF to shunt a connection (to prevent the
   data packets from reaching Bro).  For TCP connections, control
   packets are still allowed through so that Bro can continue logging
   the connection and it can stop shunting once the connection ends.

.. bro:id:: PacketFilter::shunt_host_pair

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`) : :bro:type:`bool`

   This function will use a BPF expression to shunt traffic between
   the two hosts given in the `conn_id` so that the traffic is never
   exposed to Bro's traffic processing.

.. bro:id:: PacketFilter::unshunt_host_pair

   :Type: :bro:type:`function` (id: :bro:type:`conn_id`) : :bro:type:`bool`

   Remove shunting for a host pair given as a `conn_id`.  The filter
   is not immediately removed.  It waits for the occasional filter
   update done by the `PacketFilter` framework.


