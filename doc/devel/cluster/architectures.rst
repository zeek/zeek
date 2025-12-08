=====================
Cluster Architectures
=====================

Introduction
============

Within Zeek, packet processing and :ref:`script execution <writing-scripts>` happen
serially within a single thread of execution.
Concretely, after passing a single packet through session tracking and analyzers,
Zeek drains its event queue, executing all queued events, before continuing with
the next packet.

When monitoring live traffic of any significant amount, a single Zeek process
will not have enough CPU time available to process all incoming
packets in a timely fashion. Generally, this results in packet buffers on the
network interface card (NIC) to fill and eventually results in packet drops,
causing data loss.

Most network monitoring applications solve this by horizontally scaling the
packet processing path. Zeek is no different in this respect.
The idea is to spawn individual Zeek processes, each receiving a *flow-balanced*
portion of the monitored traffic.
Flow-balancing ensures that all packets belonging to an individual flow
between two endpoints are forwarded to the same Zeek process.
The details aren't important at this point. Generally, flow-balancing
has been solved by various open-source projects or in the firmware of specialized
network cards by symmetric hashing of network packet headers.
Examples in this area are
`Linux's AF_PACKET <https://docs.kernel.org/networking/packet_mmap.html#af-packet-fanout-mode>`_,
`netmap <https://github.com/luigirizzo/netmap>`_,
`PF_RING <https://www.ntop.org/products/packet-capture/pf_ring/>`_,
`Napatech Network Streams <https://docs.napatech.com/r/Software-Architecture/Network-Streams>`_,
Intel (and others) NIC queues via AF_PACKET's ``PACKET_FANOUT_QM``
fanout setting, etc.
Head to the :ref:`Cluster Setup <cluster-setup-on-host-flow-balancing>`
section for more details around this.

In a cluster, Zeek processes that listen on a network interface are called
Zeek workers.
Conceptually, each Zeek worker process gets assigned an individual interface
via the ``-i`` command-line argument. To a degree, this controls which chunk
of traffic an individual Zeek worker will receive.

.. note::

   For AF_PACKET, all workers have the same ``-i`` argument: The interface
   name. The Linux kernel will flow-balance according to the number of running
   Zeek workers dynamically. This also means that adding or removing workers
   at runtime redistributes connections to different workers as flow-balancing
   uses a simple modulo operation over the number of workers. This may negatively
   impact data quality, so a static number of Zeek workers should be preferred.

Besides Zeek workers, three more process roles exist in a cluster:
Proxies, loggers and a central manager process.
Proxy, logger and worker processes can all be scaled independently.

.. note::

   These processes are also called nodes. And their role called node type. In this
   chapter we attempt to stick with the process terminology. Many other systems
   use the word node to describe a host running multiple services or processes and
   Zeek itself has a concept of single-node and multi-node Zeek clusters (see below),
   so this can be a bit confusing.

   On the script-level, the :zeek:see:`Cluster::node` variable contains
   ``manager``, ``worker-1``, ``proxy-1``, ``logger-1``, etc., allowing to
   identify individual processes. The :zeek:see:`Cluster::local_node_type` function
   allows to determine the role of the process a script executes on.


Zeek processes normally create log files in their working directories.
In a Zeek cluster, manager, worker and proxy processes forward their log writes
(as created via a :zeek:see:`Log::write` script-level call) in a round-robin fashion
to the running Zeek logger processes instead. The exact details depend on the Zeek
cluster backend in use. See the backend documentation for details.

A process supervisor starts and manages individual Zeek processes. Various
supervisors and deployment approaches have been prototyped, explored and used
in certain environments over the years. ZeekControl remains the de-facto
standard to run and operate a Zeek cluster as of Zeek 8.1.

Processes forming a Zeek cluster are connected via a topic-based publish/subscribe
layer. Zeek processes can subscribe to topics and receive remote
events published by other Zeek processes. All Zeek processes have visibility
into remote events published by all other process. Subscriptions use
prefix matching on topic names.

.. note::

   The publish/subscribe visibility aspect has changed in Zeek 8.1 with the
   ZeroMQ cluster backend.
   Global publish/subscribe visibility wasn't implemented with the Broker cluster
   backend, putting the burden of routing remote events through the cluster onto
   the user.
   You may stumble over scripts where a worker process publishes to the
   manager's individual topic just for the manager to re-publish the remote
   event to all workers. Backends running a centralized topology, such as ZeroMQ,
   remove the need for this detour.
   It still works, but is less efficient than sending remote events directly to
   the destination topic.

   References

   * https://github.com/zeek/zeek/issues/3917
   * https://github.com/zeek/zeek/discussions/3649

Establishing subscription at the script-level is done using the :zeek:see:`Cluster::subscribe`
function. Publishing events uses :zeek:see:`Cluster::publish`. Events are published
by providing a topic name, the event identifier and the event's arguments.

.. code-block::

   # event found_root()
   Cluster::publish("/my/topic", found_root);

   # event found_secret(secret: string)
   Cluster::publish("/my/topic", found_secret, "SeCrEt!!");

Receiving and execution of remote events is implicit: The existence of a local
event handler implies execution of received remote events with the same name.
Publishing a remote event is asynchronous. The incurred latency between different
processes depends on the cluster backend and whether all Zeek processes are located
on the same node or distributed across multiple nodes.


Single Node Examples
====================

A Zeek cluster can be deployed on a single hardware/virtual system.
This looks as follows when the system has a single monitoring NIC.

.. figure:: /images/cluster/single-system-one-nic.svg

This example depicts load-balancing of all network traffic across 8 workers.

When monitoring two NICs on the same system, the cluster looks
as follows, assuming four workers are sufficient per NIC.

.. figure:: /images/cluster/single-system-two-nics.svg


Note that while these diagrams depict just a few workers per NIC, high-performance
environments may require 100 or more Zeek workers and---depending on the loaded
scripts---up to 10s of proxies and loggers. Such environments generally require experiments,
monitoring and performance tuning to establish the appropriate number of workers,
loggers and proxies for a given hardware configuration and system.

.. note::

   Zeek loggers aggregate the logs produced by other processes and logging to
   a single file. When Zeek logs are forwarded to a messaging queue like Kafka
   or NATS instead, all log records continue to be funneled through logger processes.
   It likely would be more efficient to instead send logs to a message queue directly.

   As of Zeek 8.0, there is no ready-to-use recipe for running a logger-less cluster.


Multi Node Examples
===================

Zeek was originally developed during a time in which multi-core CPUs weren't
widely available and scaling and flow-balancing was actually done on the level
of a full hardware system.
This can still be useful today for deploying multiple smaller worker systems
with 10G NICs compared to a single large system with hundreds of CPUs and a
powerful 100G NIC. Such an architecture requires an external packet broker
that ensures consistent flow-balancing across the individual Zeek systems,
essentially introducing a separate flow-balancing layer.

Shared Publish/Subscribe Layer
------------------------------

The following diagram depicts a deployment with three individual hardware
systems with the system to the left running a single logger and manager process.
Each system runs a single proxy process (proxy-1, proxy-2 and proxy-3) and
four worker processes.
All Zeek processes can send remote events to each other through the shared
publish/subscribe layer.


.. figure:: /images/cluster/three-systems-shared-pubsub.svg


Split Publish/Subscribe Layer
-----------------------------

Sometimes, a single Zeek cluster is deployed per physical or virtual system
with a packet broker in front. In such cases, the architecture looks as follows.

.. figure:: /images/cluster/three-systems-individual-pubsub.svg

For basic network traffic analysis and protocol logging this is usually sufficient,
but in general such setups are discouraged.
If the individual systems depicted all monitor the same network segment, correlation
across different worker processes will be limited to an individual system.
Using the previous architecture where all systems operate using a shared
publish/subscribe layer will not have these limitations.


WebSocket API to the Publish/Subscribe Layer
============================================

Interacting with Zeek's publish/subscribe layer using external non-Zeek
applications is possible using :ref:`Zeek's WebSocket API <websocket-api>`.

Conventionally, the Zeek manager process listens for incoming WebSocket
connections from external applications. Starting from Zeek 8.1, the manager
process in a ZeekControl managed cluster listens on::

        ws://127.0.0.1:27759

The sketch below shows the idea.

.. figure:: /images/cluster/single-system-websocket.svg

Essentially, the manager process provides a cluster backend agnostic entry
point to Zeek's publish/subscribe layer. It is possible to start such
WebSocket entrypoints on other Zeek processes (even workers) using
:zeek:see:`Cluster::listen_websocket` within your own scripts.

As WebSocket provides a bi-directional persistent connection, which allows
non-Zeek processes to send and receive remote Zeek events that all other
connected Zeek and non-Zeek processes will see.

.. note::

   Zeek's WebSocket API does not provide any authentication or authorization
   mechanisms. Any external application can subscribe to every topic prefix
   and observe all events produced by processes in a Zeek cluster. Similarly,
   an external application may publish events to any topic it wishes.
   If this is concerning to you, place a reverse proxy like Nginx with basic
   authorization or a more advanced configuration in front of Zeek's
   WebSocket API. While Zeek supports TLS certificates for the WebSocket API,
   a fronting Nginx might be the better place to do this.

   If a single WebSocket API presents a bottleneck, an idea is to run a WebSocket
   API on all proxy processes and, again, let a fronting Nginx process perform
   load-balancing.


Operational Metrics via Prometheus
==================================

Historically, Zeek has exposed many of its operational metrics via logs
(``stats.log`` specifically) and assumed users have infrastructure in
place to load and analyze such data.
Today, Zeek logs may only be accessible to certain users and analysts, while
runtime and performance metrics are more interesting to Zeek operators.
Additionally, `Prometheus <https://prometheus.io/>`_ has become a very popular
option in the operational metrics space. Starting with version 4.1, Zeek has
moved into a direction where Prometheus exposition for operational metrics
is preferred over exporting them as classic Zeek logs.

The model is that in a Zeek cluster, every Zeek process opens a HTTP Prometheus
listener. An external Prometheus server scrapes metrics from these endpoints
at regular intervals. ZeekControl currently allocates listener ports statically.

The manager process additionally provides a ``/services.json`` endpoint for
`HTTP-based service discovery <https://prometheus.io/docs/prometheus/latest/http_sd/>`_
of all processes in a Zeek cluster.
This allows the Prometheus Server to discover all metrics endpoints via the
Zeek manager's ``/services.json`` endpoint.

Adding to the previous diagrams, this looks as follows:

.. figure:: /images/cluster/single-system-prometheus.svg

This should seamlessly work with multi-node clusters.

.. note::

   As of Zeek 7, the Zeek manager builds the ``/services.json`` response
   based on the static ``cluster-layout.zeek``. It statically knows all
   all the metric endpoints of all other processes. In the future this might
   be more dynamic. There's no actual reason for this static setup. Other
   Zeek processes could as well dynamically register their metrics endpoint
   with the manager process at runtime.
