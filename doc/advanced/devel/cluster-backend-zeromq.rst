.. _cluster_backend_zeromq:

======================
ZeroMQ Cluster Backend
======================

.. versionadded:: 7.1

Quickstart
==========

To switch a Zeek cluster with a static cluster layout over to use ZeroMQ
as cluster backend, add the following snippet to ``local.zeek``:

.. code-block:: zeek

   @load frameworks/cluster/backend/zeromq/connect


Note that the function :zeek:see:`Broker::publish` will be non-functional
and a warning emitted when used - use :zeek:see:`Cluster::publish` instead.

By default, a configuration based on hard-coded endpoints and cluster layout
information is created. For more customization, refer to the module documentation
at :doc:`cluster/backend/zeromq/main.zeek </scripts/policy/frameworks/cluster/backend/zeromq/main.zeek>`.


Architecture
============

Publish-Subscribe of Zeek Events
--------------------------------

The `ZeroMQ <https://zeromq.org/>`_ based cluster backend uses a central
XPUB/XSUB broker for publish-subscribe functionality. Zeek events published
via :zeek:see:`Cluster::publish` are distributed by this central broker to
interested nodes.

.. figure:: /images/cluster/zeromq-pubsub.png


As depicted in the figure above, each cluster node connects to the central
broker twice, once via its XPUB socket and once via its XSUB socket. This
results in two TCP connections from every cluster node to the central broker.
This setup allows every node in the cluster to see messages from all other
nodes, avoiding the need for cluster topology awareness.

.. note::

   Scalability of the central broker in production setups, but for small
   clusters on a single node, may be fast enough.

On a cluster node, the XPUB socket provides notifications about subscriptions
created by other nodes: For every subscription created by any node in
the cluster, the :zeek:see:`Cluster::Backend::ZeroMQ::subscription` event is
raised locally on every other node (unless another node had created the same
subscription previously).

This mechanism is used to discover the existence of other cluster nodes by
matching the topics with the prefix for node specific subscriptions as produced
by :zeek:see:`Cluster::nodeid_topic`.

As of now, the implementation of the central broker calls ZeroMQ's
``zmq::proxy()`` function to forward messages between the XPUB and
XSUB socket.

While the diagram above indicates the central broker being deployed separately
from Zeek cluster nodes, by default the manager node will start and run this
broker using a separate thread. There's nothing that would prevent from running
a long running central broker independently from the Zeek cluster nodes, however.

The serialization of Zeek events is done by the selected
:zeek:see:`Cluster::event_serializer` and is independent of ZeroMQ.
The central broker needs no knowledge about the chosen format, it is
only shuffling messages between nodes.


Logging
-------

While remote events always pass through the central broker, nodes connect and
send log writes directly to logger nodes in a cluster. The ZeroMQ cluster backend
leverages ZeroMQ's pipeline pattern for this functionality. That is, logger nodes
(including the manager if configured using :zeek:see:`Cluster::manager_is_logger`)
open a ZeroMQ PULL socket to receive log writes. All other nodes connect their
PUSH socket to all available PULL sockets. These connections are separate from
the publish-subscribe setup outlined above.

When sending log-writes over a PUSH socket, load balancing is done by ZeroMQ.
Individual cluster nodes do not have control over the decision which logger
node receives log writes at any given time.

.. figure:: /images/cluster/zeromq-logging.png

While the previous paragraph used "log writes", a single message to a logger
node actually contains a batch of log writes. The options :zeek:see:`Log::flush_interval`
and :zeek:see:`Log::write_buffer_size` control the frequency and maximum size
of these batches.

The serialization format used to encode such batches is controlled by the
selected :zeek:see:`Cluster::log_serializer` and is independent of ZeroMQ.

With the default serializer (:zeek:see:`Cluster::LOG_SERIALIZER_ZEEK_BIN_V1`),
every log batch on the wire has a header prepended that describes it. This allows
interpretation of log writes even by non-Zeek processes. This opens the possibility
to implement non-Zeek logger processes as long as the chosen serializer format
is understood by the receiving process. In the future, a JSON lines serialization
may be provided, allowing easier interpretation than a proprietary binary format.


Summary
-------

Combining the diagrams above, the connections between the different socket
types in a Zeek cluster looks something like the following.

.. figure:: /images/cluster/zeromq-cluster.png

