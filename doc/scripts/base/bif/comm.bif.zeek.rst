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
=========================================================== ======================================================================
:zeek:id:`Broker::endpoint_discovered`: :zeek:type:`event`  Generated when a new Broker endpoint appeared.
:zeek:id:`Broker::endpoint_unreachable`: :zeek:type:`event` Generated when the last path to a Broker endpoint has been lost.
:zeek:id:`Broker::error`: :zeek:type:`event`                Generated when an error occurs in the Broker sub-system.
:zeek:id:`Broker::internal_log_event`: :zeek:type:`event`   Generated when Broker emits an internal logging event.
:zeek:id:`Broker::peer_added`: :zeek:type:`event`           Generated when a new peering has been established.
:zeek:id:`Broker::peer_lost`: :zeek:type:`event`            Generated when the local endpoint has lost its peering with another
                                                            endpoint.
:zeek:id:`Broker::peer_removed`: :zeek:type:`event`         Generated when the local endpoint has removed its peering with another
                                                            endpoint.
:zeek:id:`Broker::status`: :zeek:type:`event`               Generated when an unspecified change occurs in Broker.
=========================================================== ======================================================================

Functions
#########
=============================================================== =
:zeek:id:`Broker::__is_outbound_peering`: :zeek:type:`function`
:zeek:id:`Broker::__listen`: :zeek:type:`function`
:zeek:id:`Broker::__node_id`: :zeek:type:`function`
:zeek:id:`Broker::__peer`: :zeek:type:`function`
:zeek:id:`Broker::__peer_no_retry`: :zeek:type:`function`
:zeek:id:`Broker::__peering_stats`: :zeek:type:`function`
:zeek:id:`Broker::__peers`: :zeek:type:`function`
:zeek:id:`Broker::__unpeer`: :zeek:type:`function`
=============================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: Broker::BrokerProtocol
   :source-code: base/bif/comm.bif.zeek 149 149

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Broker::NATIVE Broker::BrokerProtocol

      .. zeek:enum:: Broker::WEBSOCKET Broker::BrokerProtocol


Events
######
.. zeek:id:: Broker::endpoint_discovered
   :source-code: base/bif/comm.bif.zeek 78 78

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new Broker endpoint appeared.

.. zeek:id:: Broker::endpoint_unreachable
   :source-code: base/bif/comm.bif.zeek 82 82

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when the last path to a Broker endpoint has been lost.

.. zeek:id:: Broker::error
   :source-code: base/frameworks/broker/log.zeek 83 96

   :Type: :zeek:type:`event` (code: :zeek:type:`Broker::ErrorCode`, msg: :zeek:type:`string`)

   Generated when an error occurs in the Broker sub-system. This event
   reports local errors in Broker, as indicated by the provided
   :zeek:type:`Broker::ErrorCode`.


   :param code: the type of error that triggered this event.


   :param msg: a message providing additional context.

   .. zeek:see:: Broker::peer_added Broker::peer_removed Broker::peer_lost
      Broker::endpoint_discovered Broker::endpoint_unreachable Broker::status

.. zeek:id:: Broker::internal_log_event
   :source-code: base/frameworks/broker/log.zeek 98 122

   :Type: :zeek:type:`event` (lvl: :zeek:type:`Broker::LogSeverityLevel`, id: :zeek:type:`string`, description: :zeek:type:`string`)

   Generated when Broker emits an internal logging event.


   :param lvl: the severity of the event as reported by Broker.


   :param id: an identifier for the event type.


   :param description: a message providing additional context.

.. zeek:id:: Broker::peer_added
   :source-code: base/bif/comm.bif.zeek 36 36

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when a new peering has been established. Both sides of the peering
   receive this event, created independently in each endpoint. For the endpoint
   establishing the peering, the added endpoint's network information will match
   the address and port provided to :zeek:see:`Broker::peer`; for the listening
   endpoint it's the peer's TCP client's address and (likely ephemeral) TCP
   port.


   :param endpoint: the added endpoint's Broker ID and connection information.


   :param msg: a message providing additional context.

   .. zeek:see:: Broker::peer_removed Broker::peer_lost
      Broker::endpoint_discovered Broker::endpoint_unreachable
      Broker::status Broker::error

.. zeek:id:: Broker::peer_lost
   :source-code: base/bif/comm.bif.zeek 74 74

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when the local endpoint has lost its peering with another
   endpoint. This event fires when the other endpoint stops or removes the
   peering for some other reason. This event is independent of the original
   directionality of connection establishment.


   :param endpoint: the lost endpoint's Broker ID and connection information.


   :param msg: a message providing additional context.

   .. zeek:see:: Broker::peer_added Broker::peer_removed
      Broker::endpoint_discovered Broker::endpoint_unreachable
      Broker::status Broker::error

.. zeek:id:: Broker::peer_removed
   :source-code: base/bif/comm.bif.zeek 59 59

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when the local endpoint has removed its peering with another
   endpoint. This event can fire for multiple reasons, such as a local call to
   :zeek:see:`Broker::unpeer`, or because Broker autonomously decides to
   unpeer. One reason it might do this is message I/O backpressure overflow,
   meaning that the remote peer cannot keep up with the stream of messages the
   local endpoint sends it. Regardless of the cause, the remote endpoint will
   locally trigger a corresponding :zeek:see:`Broker::peer_lost` event once the
   peering ends. These events are independent of the original directionality of
   TCP connection establishment and only reflect which endpoint terminates the
   peering.


   :param endpoint: the removed endpoint's Broker ID and connection information.


   :param msg: a message providing additional context. If backpressure overflow
        caused this unpeering, the message contains the string
        *caf::sec::backpressure_overflow*.

   .. zeek:see:: Broker::peer_added Broker::peer_lost
      Broker::endpoint_discovered Broker::endpoint_unreachable
      Broker::status Broker::error

.. zeek:id:: Broker::status
   :source-code: base/bif/comm.bif.zeek 96 96

   :Type: :zeek:type:`event` (endpoint: :zeek:type:`Broker::EndpointInfo`, msg: :zeek:type:`string`)

   Generated when an unspecified change occurs in Broker. This event only fires
   when the status change isn't covered by more specific Broker events. The
   provided message string may be empty.


   :param endpoint: the Broker ID and connection information, if available,
             of the endpoint the update relates to.


   :param msg: a message providing additional context.

   .. zeek:see:: Broker::peer_added Broker::peer_removed Broker::peer_lost
      Broker::endpoint_discovered Broker::endpoint_unreachable Broker::error

Functions
#########
.. zeek:id:: Broker::__is_outbound_peering
   :source-code: base/bif/comm.bif.zeek 167 167

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`


.. zeek:id:: Broker::__listen
   :source-code: base/bif/comm.bif.zeek 155 155

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, proto: :zeek:type:`Broker::BrokerProtocol`) : :zeek:type:`port`


.. zeek:id:: Broker::__node_id
   :source-code: base/bif/comm.bif.zeek 173 173

   :Type: :zeek:type:`function` () : :zeek:type:`string`


.. zeek:id:: Broker::__peer
   :source-code: base/bif/comm.bif.zeek 158 158

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`, retry: :zeek:type:`interval`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peer_no_retry
   :source-code: base/bif/comm.bif.zeek 161 161

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`


.. zeek:id:: Broker::__peering_stats
   :source-code: base/bif/comm.bif.zeek 176 176

   :Type: :zeek:type:`function` () : :zeek:type:`BrokerPeeringStatsTable`


.. zeek:id:: Broker::__peers
   :source-code: base/bif/comm.bif.zeek 170 170

   :Type: :zeek:type:`function` () : :zeek:type:`Broker::PeerInfos`


.. zeek:id:: Broker::__unpeer
   :source-code: base/bif/comm.bif.zeek 164 164

   :Type: :zeek:type:`function` (a: :zeek:type:`string`, p: :zeek:type:`port`) : :zeek:type:`bool`



