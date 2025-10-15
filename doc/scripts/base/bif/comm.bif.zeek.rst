:tocdepth: 3

base/bif/comm.bif.zeek
======================
.. zeek:namespace:: Broker
.. zeek:namespace:: GLOBAL

Functions and events regarding broker communication mechanisms.

:Namespaces: Broker, GLOBAL

Summary
~~~~~~~
Types
#####
====================================================== =
:zeek:type:`Broker::BrokerProtocol`: :zeek:type:`enum` 
====================================================== =

Events
######
=========================================================== ================================================================
:zeek:id:`Broker::endpoint_discovered`: :zeek:type:`event`  Generated when a new Broker endpoint appeared.
:zeek:id:`Broker::endpoint_unreachable`: :zeek:type:`event` Generated when the last path to a Broker endpoint has been lost.
:zeek:id:`Broker::error`: :zeek:type:`event`                Generated when an error occurs in the Broker sub-system.
:zeek:id:`Broker::peer_added`: :zeek:type:`event`           Generated when a new peering has been established.
:zeek:id:`Broker::peer_lost`: :zeek:type:`event`            Generated when an existing peering has been lost.
:zeek:id:`Broker::peer_removed`: :zeek:type:`event`         Generated when an existing peer has been removed.
:zeek:id:`Broker::status`: :zeek:type:`event`               Generated when something changes in the Broker sub-system.
=========================================================== ================================================================

Functions
#########
========================================================= =
:zeek:id:`Broker::__listen`: :zeek:type:`function`        
:zeek:id:`Broker::__node_id`: :zeek:type:`function`       
:zeek:id:`Broker::__peer`: :zeek:type:`function`          
:zeek:id:`Broker::__peer_no_retry`: :zeek:type:`function` 
:zeek:id:`Broker::__peers`: :zeek:type:`function`         
:zeek:id:`Broker::__unpeer`: :zeek:type:`function`        
========================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Broker::BrokerProtocol
   :source-code: base/bif/comm.bif.zeek 77 77

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::NATIVE Broker::BrokerProtocol

      .. zeek:enum:: Broker::WEBSOCKET Broker::BrokerProtocol


Events
######
.. zeek:id:: Broker::endpoint_discovered
   :source-code: base/bif/comm.bif.zeek 29 29

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new Broker endpoint appeared.

.. zeek:id:: Broker::endpoint_unreachable
   :source-code: base/bif/comm.bif.zeek 33 33

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when the last path to a Broker endpoint has been lost.

.. zeek:id:: Broker::error
   :source-code: base/frameworks/broker/log.zeek 71 84

   :Type: :zeek:type:`event` (code: :zeek:type:`Broker::ErrorCode`, msg: :zeek:type:`string`)

   Generated when an error occurs in the Broker sub-system.

.. zeek:id:: Broker::peer_added
   :source-code: base/bif/comm.bif.zeek 17 17

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new peering has been established.

.. zeek:id:: Broker::peer_lost
   :source-code: base/bif/comm.bif.zeek 25 25

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peering has been lost.

.. zeek:id:: Broker::peer_removed
   :source-code: base/frameworks/broker/log.zeek 61 64

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an existing peer has been removed.

.. zeek:id:: Broker::status
   :source-code: base/bif/comm.bif.zeek 13 13

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when something changes in the Broker sub-system.

Functions
#########
.. zeek:id:: Broker::__listen
   :source-code: base/bif/comm.bif.zeek 83 83

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, proto: :zeek:type:`Broker::BrokerProtocol`) : :zeek:type:`port`


.. zeek:id:: Broker::__node_id
   :source-code: base/bif/comm.bif.zeek 98 98

   :Type: :zeek:type:`function` () : :zeek:type:`string`


.. zeek:id:: Broker::__peer
   :source-code: base/bif/comm.bif.zeek 86 86

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, retry: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peer_no_retry
   :source-code: base/bif/comm.bif.zeek 89 89

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peers
   :source-code: base/bif/comm.bif.zeek 95 95

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::PeerInfos`


.. zeek:id:: Broker::__unpeer
   :source-code: base/bif/comm.bif.zeek 92 92

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`



