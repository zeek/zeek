=====================
Cluster Architectures
=====================

Introduction
============

Within Zeek, packet processing and :ref:`script execution <writing-scripts>` happen
serially within a single thread of execution.
Concretely, after processing a single packet by session tracking and analyzers,
Zeek drains its event queue, executing all queued events, before continuing with
the next packet.

When monitoring live traffic of any significant amount (think 10s to 100s of Gbps),
a single Zeek process will not have enough CPU time available to process all incoming
packets in a timely fashion. Generally, this results in packet buffers on the
network interface card (NIC) to fill and eventually results in packet drops,
causing data loss.

Most network monitoring applications solve this by horizontally scaling the
packet processing path. Zeek is no different in this respect.
The high-level idea is to spawn individual Zeek processes. Each process receives
a *flow-balanced* portion of the monitored traffic.
Flow-balancing requires that all packets belonging to an individual flow
between two endpoints are forwarded to the same Zeek process.
The details aren't important at this point. Generally, flow-balancing
has been solved by various open-source projects or in the firmware of specialized
network cards. Examples in this area are Linux's AF_PACKET, netmap, PF_RING,
Napatech streams, Intel hardware queues via AF_PACKET's ``PACKET_FANOUT_QM``,
and more.

From Zeek's perspective, each worker gets assigned an individual interface.
In the case of AF_PACKET it is actually the same interface identifier and
the kernel does some magic behind the scenes.

In a cluster, Zeek processes that listen on a network interface are called
Zeek workers.
Besides Zeek workers, three more process roles exist in a cluster:
Proxies, loggers and a central manager process.
Proxies, loggers and workers can be independently scaled.

Zeek normally creates log files in its working directory.
In a Zeek cluster, worker processes forward their log writes (as created via
a :zeek:see:`Log::write` script-level call) in a round-robin fashion to the
Zeek logger processes in the cluster. The exact details depend on the
Zeek cluster backend in use. See the backend documentation for details.

A process supervisor starts and manages individual Zeek processes.
Various supervisors have been prototyped and explored over the years.
As of Zeek 8.0, Zeekctl is still the de-facto standard.

All processes forming a Zeek cluster are connected via
a topic-based publish subscribe layer. Zeek processes can subscribe to
topics and publish remote Zeek events to these topics. Processes do not
see events they published themselves.

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
environments may require 100 or more Zeek workers and - depending on the loaded
scripts - up to 10s of proxies. Such environments generally require experiments,
monitoring and performance tuning to establish the appropriate number of workers,
loggers and proxies for a given hardware configuration and system.

.. note::

   Zeek loggers are an artificial bottleneck in a Zeek cluster. Particular if all
   Zeek logs are forwarded to messaging queue like Kafka or NATS, it is almost
   certainly more efficient to have workers direct log writes to the message queue
   instead of funneling them through a single Zeek process. The tagline here is that
   Kafka or NATS are likely better Zeek logger process.

   As of Zeek 8.0, however, there is no ready-to-use recipe for running a logger-less
   cluster. Contributions are certainly welcome.

   For the classic central file-based logging. a single Zeek logger is useful
   as the aggregation point.


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

The following diagram depicts a three node deployment with the system to the
left running a single logger and manager process. Each system runs a single proxy
process (named proxy-1, proxy-2 and proxy-3) and four worker processes.
All Zeek processes can send events to each other through the publish subscribe
layer that each process connects to.


.. figure:: /images/cluster/three-systems-one-nic.svg


Sometimes, a single Zeek cluster is deployed per physical or virtual system.
In such cases, the architecture looks as follows.

.. figure:: /images/cluster/three-systems-independent-one-nic.svg

For basic network traffic analysis and protocol logging this is usually sufficient.
If the individual systems depicted all monitor the same network segment, correlation
across different worker processes will be limited to an individual system, however.
Using the previous architecture where all systems operate using the same publish
subscribe layer will not have this limitation.
