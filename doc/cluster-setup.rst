
.. _ZeekControl documentation: https://github.com/zeek/zeekctl

.. _cluster-setup:
 
==================
Zeek Cluster Setup
==================

.. TODO: integrate BoZ revisions

A *Zeek Cluster* is a set of systems jointly analyzing the traffic of
a network link in a coordinated fashion.  You can operate such a setup from
a central manager system easily using ZeekControl because it
hides much of the complexity of the multi-machine installation.

Cluster Architecture
====================

Zeek is not multithreaded, so once the limitations of a single processor core
are reached the only option currently is to spread the workload across many
cores, or even many physical computers. The cluster deployment scenario for
Zeek is the current solution to build these larger systems. The tools and
scripts that accompany Zeek provide the structure to easily manage many Zeek
processes examining packets and doing correlation activities but acting as
a singular, cohesive entity.  This section describes the Zeek cluster
architecture.  For information on how to configure a Zeek cluster,
see the documentation for `ZeekControl <https://github.com/zeek/zeekctl>`_.

Architecture
------------

The figure below illustrates the main components of a Zeek cluster.

.. image:: /images/deployment.png

For more specific information on the way Zeek processes are connected,
how they function, and how they communicate with each other, see the
:ref:`Broker Framework Documentation <broker-framework>`.

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

On host flow balancing
**********************

PF_RING
^^^^^^^

The PF_RING software for Linux has a "clustering" feature which will do
flow-based load balancing across a number of processes that are sniffing the
same interface.  This allows you to easily take advantage of multiple
cores in a single physical host because Zeek's main event loop is single
threaded and can't natively utilize all of the cores.  If you want to use
PF_RING, see the documentation on :ref:`how to configure Zeek with PF_RING
<pf-ring-config>`.


AF_PACKET
^^^^^^^^^

On Linux, Zeek supports `AF_PACKET sockets <https://docs.kernel.org/networking/packet_mmap.html>`_ natively.
Currently, this is provided by including the `external Zeek::AF_Packet plugin <https://github.com/zeek/zeek-af_packet-plugin>`_
in default builds of Zeek for Linux. Additional information can be found in
the project's README file.

To check the availability of the ``af_packet`` packet source, print its information using ``zeek -N``::

    zeek -N Zeek::AF_Packet
    Zeek::AF_Packet - Packet acquisition via AF_Packet (dynamic, version 3.2.0)

On FreeBSD, MacOSX, or if Zeek was built with ``--disable-af-packet``, the
plugin won't be available.

Single worker mode
""""""""""""""""""

For the most basic usage, prefix the interface with ``af_packet::`` when invoking Zeek::

    zeek -i af_packet::eth0

Generally, running Zeek this way requires a privileged user with CAP_NET_RAW
and CAP_NET_ADMIN capabilities. Linux supports file-based capabilities: A
process executing an executable with capabilities will receive these.
Using this mechanism allows to run Zeek as an unprivileged user once the file
capabilities have been added::

    sudo setcap cap_net_raw,cap_net_admin=+eip /path/to/zeek

Offloading and ethtool tuning
"""""""""""""""""""""""""""""

While not specific to AF_PACKET, it is recommended to disable any offloading
features provided by the network card or Linux networking stack when running
Zeek. This allows to see network packets as they arrive on the wire.
See this `blog post <https://blog.securityonion.net/2011/10/when-is-full-packet-capture-not-full.html>`_
for more background

Toggling these features can be done with the ``ethtool -K`` command, for example::

    IFACE=eth0
    for offload in rx tx sg tso ufo gso gro lro; do
      ethtool -K $IFACE $offload off
    done

Detailed statistics about the interface can be gathered via ``ethtool -S``.

For more details around the involved offloads consult the
`ethtool manpage <https://man7.org/linux/man-pages/man8/ethtool.8.html>`_.

Load balancing
""""""""""""""

The more interesting use-case is to use AF_PACKET to run multiple Zeek workers
and have their packet sockets join what is called a fanout group.
In such a setup, the network traffic is load-balanced across Zeek workers.
By default load balancing is based on symmetric flow hashes [#]_.

For example, running two Zeek workers listening on the same network interface,
each worker analyzing approximately half of the network traffic, can be done
as follows::

    zeek -i af_packet::eth0 &
    zeek -i af_packet::eth0 &

The fanout group is identified by an id and configurable using the
``AF_Packet::fanout_id`` constant which defaults to 23. In the example
above, both Zeek workers join the same fanout group.


.. note::

  As a caveat, within the same Linux network namespace, two Zeek processes can
  not use the same fanout group id for listening on different network interfaces.
  If this is a setup you're planning on running, configure the fanout group
  ids explicitly.
  For illustration purposes, the following starts two Zeek workers each using
  a different network interface and fanout group id::

    zeek -i af_packet::eth0 AF_Packet::fanout_id=23 &
    zeek -i af_packet::eth1 AF_Packet::fanout_id=24 &

.. warning::

  Zeek workers crashing or restarting due to running out of memory can,
  for a short period of time, disturb load balancing due to their packet
  sockets being removed and later rejoining the fanout group.
  This may be visible in Zeek logs as gaps and/or duplicated connection
  entries produced by different Zeek workers.

See :ref:`cluster-configuration` for instructions how to configure AF_PACKET
with ZeekControl.


Netmap
^^^^^^

`Netmap <https://github.com/luigirizzo/netmap>`_ is a framework for fast
packet I/O that is natively supported on FreeBSD since version 10.
On Linux it can be installed as an out-of-tree kernel module.

FreeBSD
"""""""
FreeBSD's libpcap library supports netmap natively. This allows to prefix
interface names with ``netmap:`` to instruct libpcap to open the interface
in netmap mode. For example, a single Zeek worker can leverage netmap
transparently using Zeek's default packet source as follows::

    zeek -i netmap:em0

.. warning::

  Above command will put the em0 interface into kernel-bypass mode. Network
  packets will pass directly to Zeek without being interpreted by the kernel.
  If em0 is your primary network interface, this effectively disables
  networking, including SSH connectivity.

If your network card supports multiple rings, individual Zeek workers can be
attached to these as well (this assumes the NIC does proper flow hashing in hardware)::

    zeek -i netmap:em0-0
    zeek -i netmap:em0-1

For software load balancing support, the FreeBSD source tree includes the
``lb`` tool to distribute packets into netmap pipes doing flow hashing
in user-space.

To compile and install ``lb``, ensure ``/usr/src`` is available on your
FreeBSD system, then run the following commands::

    cd /usr/src/tools/tools/netmap/
    make
    # Installs lb into /usr/local/bin
    cp /usr/obj/usr/src/`uname -m`.`uname -m`/tools/tools/netmap/lb /usr/local/bin/


To load-balance packets arriving on em0 into 4 different netmap pipes named
``zeek}0`` through ``zeek}3``, run ``lb`` as follows::

    lb -i em0 -p zeek:4
    410.154166 main [634] interface is em0
    411.377220 main [741] successfully opened netmap:em0
    411.377243 main [812] opening pipe named netmap:zeek{0/xT@1
    411.379200 main [829] successfully opened pipe #1 netmap:zeek{0/xT@1 (tx slots: 1024)
    411.379242 main [838] zerocopy enabled
    ...

Now, Zeek workers can attach to these four netmap pipes. When starting Zeek
workers manually, the respective invocations would be as follows. The ``/x``
suffix specifies exclusive mode to prevent two Zeek processes consuming packets
from the same netmap pipe::

    zeek -i netmap:zeek}0/x
    zeek -i netmap:zeek}1/x
    zeek -i netmap:zeek}2/x
    zeek -i netmap:zeek}3/x

For packet-level debugging, you can attach ``tcpdump`` to any of the netmap
pipes in read monitor mode even while Zeek workers are consuming from them::

    tcpdump -i netmap:zeek}1/r

In case libpcap's netmap support is insufficient, the external
`Zeek netmap plugin <https://github.com/zeek/zeek-netmap>`_ can be installed.

.. warning::

  When using the zeek-netmap plugin on FreeBSD, the interface specification given to Zeek
  needs to change from ``netmap:zeek}0/x`` to ``netmap::zeek}0/x`` - a single colon more.
  In the first case, Zeek uses the default libpcap packet source and passes ``netmap:zeek}0``
  as interface name. In the second case, ``netmap::`` is interpreted by Zeek and
  the netmap packet source is instantiated. The ``zeek}0/x`` part is used as
  interface name.

Linux
"""""

While netmap isn't included in the Linux kernel, it can be installed as
an out-of-tree kernel module.
See the project's `GitHub repository <https://github.com/luigirizzo/netmap>`_
for detailed instructions. This includes the ``lb`` tool for load balancing.

On Linux, the external `zeek-netmap <https://github.com/zeek/zeek-netmap>`_
packet source plugin is required, or the system's libpcap library as used by
Zeek needs to be recompiled with native netmap support. With the netmap kernel
module loaded and the Zeek plugin installed, running a Zeek worker as follows
will leverage netmap on Linux::

    zeek -i netmap::eth1

For using ``lb`` or libpcap with netmap support, refer to the commands shown
in the FreeBSD section - these are essentially the same.


.. _cluster-configuration:

Cluster Configuration
=====================

A *Zeek Cluster* is a set of systems jointly analyzing the traffic of
a network link in a coordinated fashion.  You can operate such a setup from
a central manager system easily using ZeekControl because it
hides much of the complexity of the multi-machine installation.

This section gives examples of how to set up common cluster configurations
using ZeekControl.  For a full reference on ZeekControl, see the
`ZeekControl documentation`_.

Preparing to Set up a Cluster
-----------------------------

We refer to the user account used to set up the cluster
as the "Zeek user".  When setting up a cluster the Zeek user must be set up
on all hosts, and this user must have ssh access from the manager to all
machines in the cluster, and it must work without being prompted for a
password/passphrase (for example, using ssh public key authentication).
Also, on the worker nodes this user must have access to the target
network interface in promiscuous mode.

Additional storage must be available on all hosts under the same path,
which we will call the cluster's prefix path.  We refer to this directory
as ``<prefix>``.  If you build Zeek from source, then ``<prefix>`` is
the directory specified with the ``--prefix`` configure option,
or ``/usr/local/zeek`` by default.  The Zeek user must be able to either
create this directory or, where it already exists, must have write
permission inside this directory on all hosts.

When trying to decide how to configure the Zeek nodes, keep in mind that
there can be multiple Zeek instances running on the same host.  For example,
it's possible to run a proxy and the manager on the same host.  However, it is
recommended to run workers on a different machine than the manager because
workers can consume a lot of CPU resources.  The maximum recommended
number of workers to run on a machine should be one or two less than
the number of CPU cores available on that machine.  Using a load-balancing
method (such as PF_RING) along with CPU pinning can decrease the load on
the worker machines.  Also, in order to reduce the load on the manager
process, it is recommended to have a logger in your configuration.  If a
logger is defined in your cluster configuration, then it will receive logs
instead of the manager process.

Basic Cluster Configuration
---------------------------

With all prerequisites in place, perform the following steps to set up
a Zeek cluster (do this as the Zeek user on the manager host only):

- Edit the ZeekControl configuration file, ``<prefix>/etc/zeekctl.cfg``,
  and change the value of any options to be more suitable for
  your environment.  You will most likely want to change the value of
  the ``MailTo`` and ``LogRotationInterval`` options.  A complete
  reference of all ZeekControl options can be found in the
  `ZeekControl documentation`_.

- Edit the ZeekControl node configuration file, ``<prefix>/etc/node.cfg``
  to define where logger, manager, proxies, and workers are to run.  For a
  cluster configuration, you must comment-out (or remove) the standalone node
  in that file, and either uncomment or add node entries for each node
  in your cluster (logger, manager, proxy, and workers).  For example, if you
  wanted to run five Zeek nodes (two workers, one proxy, a logger, and a
  manager) on a cluster consisting of three machines, your cluster
  configuration would look like this::

    [logger]
    type=logger
    host=10.0.0.10

    [manager]
    type=manager
    host=10.0.0.10

    [proxy-1]
    type=proxy
    host=10.0.0.10

    [worker-1]
    type=worker
    host=10.0.0.11
    interface=eth0

    [worker-2]
    type=worker
    host=10.0.0.12
    interface=eth0

  For a complete reference of all options that are allowed in the ``node.cfg``
  file, see the `ZeekControl documentation`_.

- Edit the network configuration file ``<prefix>/etc/networks.cfg``.  This
  file lists all of the networks which the cluster should consider as local
  to the monitored environment.

- Install Zeek on all machines in the cluster using ZeekControl::

    > zeekctl install

- See the `ZeekControl documentation`_
  for information on setting up a cron job on the manager host that can
  monitor the cluster.

AF_PACKET Cluster Configuration
-------------------------------

Since version 5.2, Zeek includes AF_PACKET as a native packet source. This
provides an easy and efficient capture mechanism for Linux users.

Adapt the worker section in ZeekControl's ``node.cfg`` file with the
following entries, assuming running four worker processes listening on ``eth0`` ::

    [worker-1]
    type=worker
    host=10.0.0.11
    interface=eth0
    lb_method=af_packet
    lb_procs=4

The specific options are ``lb_method=af_packet`` and ``lb_procs=4``.
If listening on two or more interfaces on the same host is a requirement,
remember to set a unique ``fanout_id`` using the node option ``af_packet_fanout_id``::

    [worker-1-eth0]
    type=worker
    host=10.0.0.11
    interface=eth0
    lb_method=af_packet
    lb_procs=4
    af_packet_fanout_id=20

    [worker-1-eth1]
    type=worker
    host=10.0.0.11
    interface=eth1
    lb_method=af_packet
    lb_procs=4
    af_packet_fanout_id=21

Pinning the worker processes to individual CPU cores can improve performance.
Use the node's option ``pin_cpus=4,5,6,7``, listing as many CPU numbers as
processes at appropriate offsets.

.. _pf-ring-config:

PF_RING Cluster Configuration
-----------------------------

`PF_RING <https://www.ntop.org/products/packet-capture/pf_ring/>`_ allows speeding up the
packet capture process by installing a new type of socket in Linux systems.
It supports 10Gbit hardware packet filtering using standard network adapters,
and user-space DNA (Direct NIC Access) for fast packet capture/transmission.

.. note::

   Unless you have evaluated to specifically require PF_RING, consider using
   AF_PACKET first and test if it fulfills your requirements. AF_PACKET has
   been integrated into Zeek since version 5.2. It's a bit easier to get
   started with as it does not require an out of tree Linux kernel module.

Head over to :ref:`cluster-pf-ring` for more details.

.. toctree::
   :hidden:

   cluster/pf_ring


.. [#] Some Linux kernel versions between 3.10 and 4.7 might exhibit
       a bug that prevents the required symmetric hashing. The script available
       in the GitHub project `can-i-use-afpacket-fanout <https://github.com/JustinAzoff/can-i-use-afpacket-fanout>`_
       can be used to verify whether ``PACKET_FANOUT`` works as expected.

       This issue has been fixed in all stable kernels for at least 5 years.
       You're unlikely to be affected.
