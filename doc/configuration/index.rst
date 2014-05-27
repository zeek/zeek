
.. _configuration:

=====================
Cluster Configuration
=====================

.. contents::

A *Bro Cluster* is a set of systems jointly analyzing the traffic of
a network link in a coordinated fashion.  You can operate such a setup from
a central manager system easily using BroControl because BroControl
hides much of the complexity of the multi-machine installation.

This section gives examples of how to setup common cluster configurations
using BroControl.  For a full reference on BroControl, see the
:doc:`BroControl <../components/broctl/README>` documentation.


Preparing to Setup a Cluster
============================

In this document we refer to the user account used to set up the cluster
as the "Bro user".  When setting up a cluster the Bro user must be set up
on all hosts, and this user must have ssh access from the manager to all
machines in the cluster, and it must work without being prompted for a
password/passphrase (for example, using ssh public key authentication).
Also, on the worker nodes this user must have access to the target
network interface in promiscuous mode.

Additional storage must be available on all hosts under the same path,
which we will call the cluster's prefix path.  We refer to this directory
as ``<prefix>``.  If you build Bro from source, then ``<prefix>`` is
the directory specified with the ``--prefix`` configure option,
or ``/usr/local/bro`` by default.  The Bro user must be able to either
create this directory or, where it already exists, must have write
permission inside this directory on all hosts.

When trying to decide how to configure the Bro nodes, keep in mind that
there can be multiple Bro instances running on the same host.  For example,
it's possible to run a proxy and the manager on the same host.  However, it is
recommended to run workers on a different machine than the manager because
workers can consume a lot of CPU resources.  The maximum recommended
number of workers to run on a machine should be one or two less than
the number of CPU cores available on that machine.  Using a load-balancing
method (such as PF_RING) along with CPU pinning can decrease the load on
the worker machines.


Basic Cluster Configuration
===========================

With all prerequisites in place, perform the following steps to setup
a Bro cluster (do this as the Bro user on the manager host only):

- Edit the BroControl configuration file, ``<prefix>/etc/broctl.cfg``,
  and change the value of any BroControl options to be more suitable for
  your environment.  You will most likely want to change the value of
  the ``MailTo`` and ``LogRotationInterval`` options.  A complete
  reference of all BroControl options can be found in the
  :doc:`BroControl <../components/broctl/README>` documentation.

- Edit the BroControl node configuration file, ``<prefix>/etc/node.cfg``
  to define where manager, proxies, and workers are to run.  For a cluster
  configuration, you must comment-out (or remove) the standalone node
  in that file, and either uncomment or add node entries for each node
  in your cluster (manager, proxy, and workers).  For example, if you wanted
  to run four Bro nodes (two workers, one proxy, and a manager) on a cluster
  consisting of three machines, your cluster configuration would look like
  this::

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
  file, see the :doc:`BroControl <../components/broctl/README>` documentation.

- Edit the network configuration file ``<prefix>/etc/networks.cfg``.  This
  file lists all of the networks which the cluster should consider as local
  to the monitored environment.

- Install workers and proxies using BroControl::

    > broctl install

- Some tasks need to be run on a regular basis. On the manager node,
  insert a line like this into the crontab of the user running the
  cluster::

      0-59/5 * * * * <prefix>/bin/broctl cron

  (Note: if you are editing the system crontab instead of a user's own
  crontab, then you need to also specify the user which the command
  will be run as. The username must be placed after the time fields
  and before the broctl command.)

  Note that on some systems (FreeBSD in particular), the default PATH
  for cron jobs does not include the directories where bash and python
  are installed (the symptoms of this problem would be that "broctl cron"
  works when run directly by the user, but does not work from a cron job).
  To solve this problem, you would either need to create symlinks
  to bash and python in a directory that is in the default PATH for
  cron jobs, or specify a new PATH in the crontab.


PF_RING Cluster Configuration
=============================

`PF_RING <http://www.ntop.org/products/pf_ring/>`_ allows speeding up the
packet capture process by installing a new type of socket in Linux systems.
It supports 10Gbit hardware packet filtering using standard network adapters,
and user-space DNA (Direct NIC Access) for fast packet capture/transmission.

Installing PF_RING
^^^^^^^^^^^^^^^^^^

1. Download and install PF_RING for your system following the instructions
   `here <http://www.ntop.org/get-started/download/#PF_RING>`_.  The following
   commands will install the PF_RING libraries and kernel module (replace
   the version number 5.6.2 in this example with the version that you
   downloaded)::

     cd /usr/src
     tar xvzf PF_RING-5.6.2.tar.gz
     cd PF_RING-5.6.2/userland/lib
     ./configure --prefix=/opt/pfring
     make install

     cd ../libpcap
     ./configure --prefix=/opt/pfring
     make install

     cd ../tcpdump-4.1.1
     ./configure --prefix=/opt/pfring
     make install

     cd ../../kernel
     make install

     modprobe pf_ring enable_tx_capture=0 min_num_slots=32768

   Refer to the documentation for your Linux distribution on how to load the
   pf_ring module at boot time.  You will need to install the PF_RING
   library files and kernel module on all of the workers in your cluster.

2. Download the Bro source code.

3. Configure and install Bro using the following commands::

     ./configure --with-pcap=/opt/pfring
     make
     make install

4. Make sure Bro is correctly linked to the PF_RING libpcap libraries::

     ldd /usr/local/bro/bin/bro | grep pcap
           libpcap.so.1 => /opt/pfring/lib/libpcap.so.1 (0x00007fa6d7d24000)

5. Configure BroControl to use PF_RING (explained below).

6. Run "broctl install" on the manager.  This command will install Bro and
   all required scripts to the other machines in your cluster.

Using PF_RING
^^^^^^^^^^^^^

In order to use PF_RING, you need to specify the correct configuration
options for your worker nodes in BroControl's node configuration file.
Edit the ``node.cfg`` file and specify ``lb_method=pf_ring`` for each of
your worker nodes.  Next, use the ``lb_procs`` node option to specify how
many Bro processes you'd like that worker node to run, and optionally pin
those processes to certain CPU cores with the ``pin_cpus`` option (CPU
numbering starts at zero).  The correct ``pin_cpus`` setting to use is
dependent on your CPU architecture (Intel and AMD systems enumerate
processors in different ways).  Using the wrong ``pin_cpus`` setting
can cause poor performance.  Here is what a worker node entry should
look like when using PF_RING and CPU pinning::

   [worker-1]
   type=worker
   host=10.0.0.50
   interface=eth0
   lb_method=pf_ring
   lb_procs=10
   pin_cpus=2,3,4,5,6,7,8,9,10,11


Using PF_RING+DNA with symmetric RSS
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You must have a PF_RING+DNA license in order to do this.  You can sniff
each packet only once.

1. Load the DNA NIC driver (i.e. ixgbe) on each worker host.

2. Run "ethtool -L dna0 combined 10" (this will establish 10 RSS queues
   on your NIC) on each worker host.  You must make sure that you set the
   number of RSS queues to the same as the number you specify for the
   lb_procs option in the node.cfg file.

3. On the manager, configure your worker(s) in node.cfg::

       [worker-1]
       type=worker
       host=10.0.0.50
       interface=dna0
       lb_method=pf_ring
       lb_procs=10


Using PF_RING+DNA with pfdnacluster_master
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You must have a PF_RING+DNA license and a libzero license in order to do
this.  You can load balance between multiple applications and sniff the
same packets multiple times with different tools.

1. Load the DNA NIC driver (i.e. ixgbe) on each worker host.

2. Run "ethtool -L dna0 1" (this will establish 1 RSS queues on your NIC)
   on each worker host.

3. Run the pfdnacluster_master command on each worker host.  For example::

       pfdnacluster_master -c 21 -i dna0 -n 10

   Make sure that your cluster ID (21 in this example) matches the interface
   name you specify in the node.cfg file.  Also make sure that the number
   of processes you're balancing across (10 in this example) matches
   the lb_procs option in the node.cfg file.

4. If you are load balancing to other processes, you can use the
   pfringfirstappinstance variable in broctl.cfg to set the first
   application instance that Bro should use.  For example, if you are running
   pfdnacluster_master with "-n 10,4" you would set
   pfringfirstappinstance=4.  Unfortunately that's still a global setting
   in broctl.cfg at the moment but we may change that to something you can
   set in node.cfg eventually.

5. On the manager, configure your worker(s) in node.cfg::

       [worker-1]
       type=worker
       host=10.0.0.50
       interface=dnacluster:21
       lb_method=pf_ring
       lb_procs=10

