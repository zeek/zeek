:orphan:

Package: policy/frameworks/cluster/backend/zeromq
=================================================


:doc:`/scripts/policy/frameworks/cluster/backend/zeromq/__load__.zeek`


:doc:`/scripts/policy/frameworks/cluster/backend/zeromq/main.zeek`

   ZeroMQ cluster backend support.

   Overview

   For publish-subscribe functionality, one node in the Zeek cluster spawns a
   thread running a central broker listening on a XPUB and XSUB socket.
   These sockets are connected via `zmq_proxy() <https://libzmq.readthedocs.io/en/latest/zmq_proxy.html>`_.
   All other nodes connect to this central broker with their own XSUB and
   XPUB sockets, establishing a global many-to-many publish-subscribe system
   where each node sees subscriptions and messages from all other nodes in a
   Zeek cluster. ZeroMQ's `publish-subscribe pattern <http://api.zeromq.org/4-2:zmq-socket#toc9>`_
   documentation may be a good starting point. Elsewhere in ZeroMQ's documentation,
   the central broker is also called `forwarder <http://api.zeromq.org/4-2:zmq-proxy#toc5>`_.

   For remote logging functionality, the ZeroMQ `pipeline pattern <http://api.zeromq.org/4-2:zmq-socket#toc14>`_
   is used. All logger nodes listen on a PULL socket. Other nodes connect
   via PUSH sockets to all of the loggers. Concretely, remote logging
   functionality is not publish-subscribe, but instead leverages ZeroMQ's
   built-in load-balancing functionality provided by PUSH and PULL
   sockets.

   The ZeroMQ cluster backend technically allows to run a non-Zeek central
   broker (it only needs to offer XPUB and XSUB sockets). Further, it is
   possible to run non-Zeek logger nodes. All a logger node needs to do is
   open a ZeroMQ PULL socket and interpret the format used by Zeek nodes
   to send their log writes.

   Overload Behavior

   The ZeroMQ cluster backend by default drops outgoing and incoming events
   when the Zeek cluster is overloaded. Dropping of outgoing events is governed
   by the :zeek:see:`Cluster::Backend::ZeroMQ::xpub_sndhwm` setting. This
   is the High Water Mark (HWM) for the local XPUB socket's queue. Once reached,
   any outgoing events are dropped until there's room in the socket's queue again.
   The metric ``zeek_cluster_zeromq_xpub_drops_total`` is incremented for every
   dropped event.

   For incoming events, the :zeek:see:`Cluster::Backend::ZeroMQ::onloop_queue_hwm`
   setting is used. Remote events received via the local XSUB socket are first
   enqueued as raw event messages for processing on Zeek's main event loop.
   When this queue is full due to more remote events incoming than Zeek
   can possibly process in an event loop iteration, incoming events are dropped
   and the ``zeek_cluster_zeromq_onloop_drops_total`` metric is incremented.

   Incoming log batches or subscription and unsubscription events are passed
   through the onloop queue, but the HWM does currently not apply to them. The
   assumption is that 1) these are not frequent and 2) more important than
   arbitrary publish-subscribe events.

   To avoid dropping any events (e.g. for performance testing or offline PCAP
   processing), the recommended strategy is to set both
   :zeek:see:`Cluster::Backend::ZeroMQ::xpub_sndhwm` and
   :zeek:see:`Cluster::Backend::ZeroMQ::onloop_queue_hwm` to ``0``,
   disabling the HWM and dropping logic. It is up to the user to monitor CPU
   and memory usage of individual nodes to avoid overloading and running into
   out-of-memory situations.

   As a Zeek operator, you should monitor ``zeek_cluster_zeromq_xpub_drops_total``
   and ``zeek_cluster_zeromq_onloop_drops_total``. Any non-zero values for these
   metrics indicate an overloaded Zeek cluster. See the the cluster telemetry
   options :zeek:see:`Cluster::Telemetry::core_metrics` and
   :zeek:see:`Cluster::Telemetry::websocket_metrics` for ways to get a better
   understanding about the events published and received.

:doc:`/scripts/policy/frameworks/cluster/backend/zeromq/connect.zeek`

   Establish ZeroMQ connectivity with the broker.

