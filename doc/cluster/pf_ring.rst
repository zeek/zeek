.. _cluster-pf-ring:

===================
PF_RING Setup Guide
===================

.. note::

   PF_RING versions before 8.8.0 did not work correctly with Zeek's ``libkqueue``
   based IO loop. For best performance, please upgrade to PF_RING 8.8.0 or later.

   References:
     * https://github.com/ntop/PF_RING/issues/878
     * https://community.zeek.org/t/performance-issues-after-upgrade-to-zeek-6/7094

Installing PF_RING
******************

1. Download and install PF_RING for your system following the instructions
   `here <https://www.ntop.org/guides/pf_ring/get_started/index.html>`_. The following
   commands will install the PF_RING libraries and kernel module (replace
   the version number 9.2.0 in this example with the version that you
   downloaded)::

     cd /usr/src
     tar xvzf PF_RING-9.2.0.tar.gz
     cd PF_RING-9.2.0/userland/lib
     ./configure --prefix=/opt/pfring
     make install

     cd ../libpcap
     ./configure --prefix=/opt/pfring
     make install

     cd ../tcpdump
     ./configure --prefix=/opt/pfring
     make install

     cd ../../kernel
     make
     make install

     modprobe pf_ring enable_tx_capture=0 min_num_slots=32768

   Refer to the documentation for your Linux distribution on how to load the
   pf_ring module at boot time.  You will need to install the PF_RING
   library files and kernel module on all of the workers in your cluster.

2. Download the Zeek source code.

3. Configure and install Zeek using the following commands::

     ./configure --with-pcap=/opt/pfring
     make
     make install

4. Make sure Zeek is correctly linked to the PF_RING libpcap libraries::

     ldd /usr/local/zeek/bin/zeek | grep pcap
           libpcap.so.1 => /opt/pfring/lib/libpcap.so.1 (0x00007fa6d7d24000)

5. Configure ZeekControl to use PF_RING (explained below).

6. Run "zeekctl install" on the manager.  This command will install Zeek and
   required scripts to all machines in your cluster.

Using PF_RING
*************

In order to use PF_RING, you need to specify the correct configuration
options for your worker nodes in ZeekControl's node configuration file.
Edit the ``node.cfg`` file and specify ``lb_method=pf_ring`` for each of
your worker nodes.  Next, use the ``lb_procs`` node option to specify how
many Zeek processes you'd like that worker node to run, and optionally pin
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
************************************

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
******************************************

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
   pfringfirstappinstance variable in zeekctl.cfg to set the first
   application instance that Zeek should use.  For example, if you are running
   pfdnacluster_master with "-n 10,4" you would set
   pfringfirstappinstance=4.  Unfortunately that's still a global setting
   in zeekctl.cfg at the moment but we may change that to something you can
   set in node.cfg eventually.

5. On the manager, configure your worker(s) in node.cfg::

       [worker-1]
       type=worker
       host=10.0.0.50
       interface=dnacluster:21
       lb_method=pf_ring
       lb_procs=10
