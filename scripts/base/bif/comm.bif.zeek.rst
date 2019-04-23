:tocdepth: 3

base/bif/comm.bif.zeek
======================
.. zeek:namespace:: Broker
.. zeek:namespace:: GLOBAL

Functions and events regarding Bro's broker communication mechanisms.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Events
######
=================================================== ==========================================================
:zeek:id:`Broker::error`: :zeek:type:`event`        Generated when an error occurs in the Broker sub-system.
:zeek:id:`Broker::peer_added`: :zeek:type:`event`   Generated when a new peering has been established.
:zeek:id:`Broker::peer_lost`: :zeek:type:`event`    Generated when an existing peering has been lost.
:zeek:id:`Broker::peer_removed`: :zeek:type:`event` Generated when an existing peer has been removed.
:zeek:id:`Broker::status`: :zeek:type:`event`       Generated when something changes in the Broker sub-system.
=================================================== ==========================================================

Functions
#########
=================================================== =
:zeek:id:`Broker::__listen`: :zeek:type:`function`  
:zeek:id:`Broker::__node_id`: :zeek:type:`function` 
:zeek:id:`Broker::__peer`: :zeek:type:`function`    
:zeek:id:`Broker::__peers`: :zeek:type:`function`   
:zeek:id:`Broker::__unpeer`: :zeek:type:`function`  
=================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: Broker::error

   :Type: :zeek:type:`event` (code: :zeek:type:`Broker::ErrorCode`, msg: :zeek:type:`string`)

   Generated when an error occurs in the Broker sub-system.

.. zeek:id:: Broker::peer_added

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new peering has been established.

.. zeek:id:: Broker::peer_lost

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peering has been lost.

.. zeek:id:: Broker::peer_removed

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peer has been removed.

.. zeek:id:: Broker::status

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when something changes in the Broker sub-system.

Functions
#########
.. zeek:id:: Broker::__listen

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`port`


.. zeek:id:: Broker::__node_id

   :Type: :zeek:type:`function` () : :zeek:type:`string`


.. zeek:id:: Broker::__peer

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, retry: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peers

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::PeerInfos`


.. zeek:id:: Broker::__unpeer

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`



