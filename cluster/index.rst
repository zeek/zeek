
====================
Cluster Architecture
====================


Zeek is not multithreaded, so once the limitations of a single processor core
are reached the only option currently is to spread the workload across many
cores, or even many physical computers. The cluster deployment scenario for
Zeek is the current solution to build these larger systems. The tools and
scripts that accompany Zeek provide the structure to easily manage many Zeek
processes examining packets and doing correlation activities but acting as
a singular, cohesive entity.  This document describes the Zeek cluster
architecture.  For information on how to configure a Zeek cluster,
see the documentation for `ZeekControl <https://github.com/zeek/zeekctl>`_.

Architecture
---------------

The figure below illustrates the main components of a Zeek cluster.

.. image:: /images/deployment.png

For more specific information on the way Zeek processes are connected,
how they function, and how they communicate with each other, see the
:ref:`Broker Framework Documentation <brokercomm-framework>`.

Tap
***
The tap is a mechanism that splits the packet stream in order to make a copy
available for inspection. Examples include the monitoring port on a switch
and an optical splitter on fiber networks.

Frontend
********
The frontend is a discrete hardware device or on-host technique that splits
traffic into many streams or flows. The Zeek binary does not do this job.
There are numerous ways to accomplish this task, some of which are described
below in `Frontend Options`_.

Manager
*******
The manager is a Zeek process that has two primary jobs.  It receives log
messages and notices from the rest of the nodes in the cluster using the Zeek
communications protocol (note that if you use a separate logger node, then the
logger receives all logs instead of the manager).  The result
is a single log instead of many discrete logs that you have to
combine in some manner with post-processing.
The manager also supports other functionality and analysis which
requires a centralized, global view of events or data.

Logger
******
A logger is an optional Zeek process that receives log messages from the
rest of the nodes in the cluster using the Zeek communications protocol.
The purpose of having a logger receive logs instead of the manager is
to reduce the load on the manager.  If no logger is needed, then the
manager will receive logs instead.

Proxy
*****
A proxy is a Zeek process that may be used to offload data storage or
any arbitrary workload.  A cluster may contain multiple proxy nodes.
The default scripts that come with Zeek make minimal use of proxies, so
a single one may be sufficient, but customized use of them to partition
data or workloads provides greater cluster scalability potential than
just doing similar tasks on a single, centralized Manager node.

Zeek processes acting as proxies don't tend to be extremely hard on CPU
or memory and users frequently run proxy processes on the same physical
host as the manager.

Worker
******
The worker is the Zeek process that sniffs network traffic and does protocol
analysis on the reassembled traffic streams.  Most of the work of an active
cluster takes place on the workers and as such, the workers typically
represent the bulk of the Zeek processes that are running in a cluster.
The fastest memory and CPU core speed you can afford is recommended
since all of the protocol parsing and most analysis will take place here.
There are no particular requirements for the disks in workers since almost all
logging is done remotely to the manager, and normally very little is written
to disk.

The rule of thumb we have followed recently is to allocate approximately 1
core for every 250Mbps of traffic that is being analyzed. However, this
estimate could be extremely traffic mix-specific.  It has generally worked
for mixed traffic with many users and servers.  For example, if your traffic
peaks around 2Gbps (combined) and you want to handle traffic at peak load,
you may want to have 8 cores available (2048 / 250 == 8.2).  If the 250Mbps
estimate works for your traffic, this could be handled by 2 physical hosts
dedicated to being workers with each one containing a quad-core processor.

Once a flow-based load balancer is put into place this model is extremely
easy to scale. It is recommended that you estimate the amount of
hardware you will need to fully analyze your traffic.  If more is needed it's
relatively easy to increase the size of the cluster in most cases.

Frontend Options
----------------

There are many options for setting up a frontend flow distributor.  In many
cases it is beneficial to do multiple stages of flow distribution
on the network and on the host.

Discrete hardware flow balancers
********************************

cPacket
^^^^^^^

If you are monitoring one or more 10G physical interfaces, the recommended
solution is to use either a cFlow or cVu device from cPacket because they
are used successfully at a number of sites.  These devices will perform
layer-2 load balancing by rewriting the destination Ethernet MAC address
to cause each packet associated with a particular flow to have the same
destination MAC.  The packets can then be passed directly to a monitoring
host where each worker has a BPF filter to limit its visibility to only that
stream of flows, or onward to a commodity switch to split the traffic out to
multiple 1G interfaces for the workers.  This greatly reduces
costs since workers can use relatively inexpensive 1G interfaces.

OpenFlow Switches
^^^^^^^^^^^^^^^^^

We are currently exploring the use of OpenFlow based switches to do flow-based
load balancing directly on the switch, which greatly reduces frontend
costs for many users.  This document will be updated when we have more
information.

On host flow balancing
**********************

PF_RING
^^^^^^^

The PF_RING software for Linux has a "clustering" feature which will do
flow-based load balancing across a number of processes that are sniffing the
same interface.  This allows you to easily take advantage of multiple
cores in a single physical host because Zeek's main event loop is single
threaded and can't natively utilize all of the cores.  If you want to use
PF_RING, see the documentation on `how to configure Zeek with PF_RING
<https://www.zeek.org/documentation/load-balancing.html>`_.

Netmap
^^^^^^

FreeBSD has an in-progress project named Netmap which will enable flow-based
load balancing as well.  When it becomes viable for real world use, this
document will be updated.

Click! Software Router
^^^^^^^^^^^^^^^^^^^^^^

Click! can be used for flow based load balancing with a simple configuration.
This solution is not recommended on
Linux due to Zeek's PF_RING support and only as a last resort on other
operating systems since it causes a lot of overhead due to context switching
back and forth between kernel and userland several times per packet.
