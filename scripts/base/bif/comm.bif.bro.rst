:tocdepth: 3

base/bif/comm.bif.bro
=====================
.. bro:namespace:: Broker
.. bro:namespace:: GLOBAL

Functions and events regarding Bro's broker communication mechanisms.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Events
######
================================================= ==========================================================
:bro:id:`Broker::error`: :bro:type:`event`        Generated when an error occurs in the Broker sub-system.
:bro:id:`Broker::peer_added`: :bro:type:`event`   Generated when a new peering has been established.
:bro:id:`Broker::peer_lost`: :bro:type:`event`    Generated when an existing peering has been lost.
:bro:id:`Broker::peer_removed`: :bro:type:`event` Generated when an existing peer has been removed.
:bro:id:`Broker::status`: :bro:type:`event`       Generated when something changes in the Broker sub-system.
================================================= ==========================================================

Functions
#########
================================================= =
:bro:id:`Broker::__listen`: :bro:type:`function`  
:bro:id:`Broker::__node_id`: :bro:type:`function` 
:bro:id:`Broker::__peer`: :bro:type:`function`    
:bro:id:`Broker::__peers`: :bro:type:`function`   
:bro:id:`Broker::__unpeer`: :bro:type:`function`  
================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: Broker::error

   :Type: :bro:type:`event` (code: :bro:type:`Broker::ErrorCode`, msg: :bro:type:`string`)

   Generated when an error occurs in the Broker sub-system.

.. bro:id:: Broker::peer_added

   :Type: :bro:type:`event` (endpoint: :bro:type:`Broker::EndpointInfo`, msg: :bro:type:`string`)

   Generated when a new peering has been established.

.. bro:id:: Broker::peer_lost

   :Type: :bro:type:`event` (endpoint: :bro:type:`Broker::EndpointInfo`, msg: :bro:type:`string`)

   Generated when an existing peering has been lost.

.. bro:id:: Broker::peer_removed

   :Type: :bro:type:`event` (endpoint: :bro:type:`Broker::EndpointInfo`, msg: :bro:type:`string`)

   Generated when an existing peer has been removed.

.. bro:id:: Broker::status

   :Type: :bro:type:`event` (endpoint: :bro:type:`Broker::EndpointInfo`, msg: :bro:type:`string`)

   Generated when something changes in the Broker sub-system.

Functions
#########
.. bro:id:: Broker::__listen

   :Type: :bro:type:`function` (a: :bro:type:`string`, p: :bro:type:`port`) : :bro:type:`port`


.. bro:id:: Broker::__node_id

   :Type: :bro:type:`function` () : :bro:type:`string`


.. bro:id:: Broker::__peer

   :Type: :bro:type:`function` (a: :bro:type:`string`, p: :bro:type:`port`, retry: :bro:type:`interval`) : :bro:type:`bool`


.. bro:id:: Broker::__peers

   :Type: :bro:type:`function` () : :bro:type:`Broker::PeerInfos`


.. bro:id:: Broker::__unpeer

   :Type: :bro:type:`function` (a: :bro:type:`string`, p: :bro:type:`port`) : :bro:type:`bool`



