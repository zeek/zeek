
.. _deploy-systemd:

============================
Deploying Zeek using systemd
============================

.. versionadded:: 8.1

Zeek includes a `systemd generator <https://www.freedesktop.org/software/systemd/man/latest/systemd.generator.html>`_
that reads the ``<PREFIX>/etc/zeek/zeek.conf`` configuration file and instantiates systemd
unit files for the manager, logger, proxy and worker processes accordingly.
The generator is installed at ``<PREFIX>/bin/zeek-systemd-generator``.

.. note::

   ``zeek.conf`` file's focus is an opinionated Zeek deployment tailored for
   appliance or container use cases. It presents an alternative to a
   :ref:`ZeekControl <cluster-configuration>` managed deployment.


Installation
============

After installing Zeek on your system, link Zeek's systemd generator into one
of the standard generator directories:

.. code:: console

   # ln -s <PREFIX>/bin/zeek-systemd-generator /etc/systemd/system-generators/


Single Host Walkthrough
=======================

For a small Zeek deployment listening with 2 workers on eth1, using
AF_PACKET for flow-balancing, plus running the manager and one logger
and one proxy process, the following minimal configuration is sufficient:

.. code:: ini

    interface = af_packet::eth1
    workers = 2

This minimal format is termed the section-less configuration style.
See the :ref:`systemd_multiple_interfaces` section for the more verbose INI-style
configuration that is required when you want to listen on multiple interfaces.

After running ``systemctl daemon-reload``, which executes ``zeek-systemd-generator``,
the generated unit files are found in the ``/run/systemd/generator`` directory of
the system where they can be inspected:

.. code:: console

    # tree /run/systemd/generator | grep zeek
    ├── zeek-archiver.service
    ├── zeek-logger@.service
    ├── zeek-manager.service
    ├── zeek-proxy@.service
    ├── zeek-setup.service
    ├── zeek.target
    ├── zeek.target.wants
    │   ├── zeek-archiver.service -> ../zeek-archiver.service
    │   ├── zeek-logger@1.service -> ../zeek-logger@.service
    │   ├── zeek-manager.service -> ../zeek-manager.service
    │   ├── zeek-proxy@1.service -> ../zeek-proxy@.service
    │   ├── zeek-setup.service -> ../zeek-setup.service
    │   ├── zeek-worker@1.service -> ../zeek-worker@.service
    │   └── zeek-worker@2.service -> ../zeek-worker@.service
    ├── zeek-worker@1.service.d
    │   └── 10-zeek-systemd-generator.conf
    ├── zeek-worker@2.service.d
    │   └── 10-zeek-systemd-generator.conf
    └── zeek-worker@.service


If you're curious about all these different unit files and processes,
take a look at :ref:`devel-cluster-architectures` and :ref:`devel-cluster-spawning-cluster`.
Zeek is a relatively complex multi-process application.


Start Zeek using ``systemctl`` with the ``zeek.target`` unit:

.. code:: console

    # systemctl start zeek.target

Inspect the status of the individual processes with ``systemd-cgtop zeek.slice``
or ``systemctl status zeek.slice``:

.. code:: console

    # systemctl status zeek.slice
    ● zeek.slice - Slice /zeek
     Loaded: loaded
     Active: active since Mon 2026-04-20 17:40:28 CEST; 3 days ago
      Tasks: 90
     Memory: 477.8M (peak: 2.5G swap: 0B swap peak: 999.1M)
        CPU: 1h 9min 36.236s
     CGroup: /zeek.slice
             ├─zeek-archiver.slice
             │ └─zeek-archiver.service
             │   └─2601102 /opt/zeek/bin/zeek-archiver /opt/zeek/var/spool/zeek/log-queue /opt/zeek/var/logs/zeek
             ├─zeek-loggers.slice
             │ └─zeek-logger@1.service
             │   └─2601103 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
             ├─zeek-manager.slice
             │ └─zeek-manager.service
             │   └─2601104 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
             ├─zeek-proxies.slice
             │ └─zeek-proxy@1.service
             │   └─2601112 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
             └─zeek-workers.slice
               ├─zeek-worker@1.service
               │ └─2601123 /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
               └─zeek-worker@2.service
                 └─2601107 /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq

To inspect the logs of the individual Zeek processes, use ``journalctl``, maybe
together with ``--reverse`` or ``--follow``:

.. code:: console

    # journalctl --follow -u 'zeek*'
    Apr 24 13:42:14 tinkyx1 systemd[1]: Starting zeek-worker@1.service - Zeek Worker 1...
    Apr 24 13:42:14 tinkyx1 systemd[1]: Started zeek-worker@2.service - Zeek Worker 2.
    Apr 24 13:42:14 tinkyx1 systemd[1]: Started zeek-worker@1.service - Zeek Worker 1.
    Apr 24 13:42:14 tinkyx1 systemd[1]: Reached target zeek.target - The Zeek Network Security Monitor.
    Apr 24 13:42:15 tinkyx1 zeek-worker-2[2602816]: listening on eth1
    Apr 24 13:42:15 tinkyx1 zeek-worker-1[2602825]: listening on eth1
    Apr 24 13:46:44 tinkyx1 systemd[1]: zeek-worker@1.service: Main process exited, code=dumped, status=6/ABRT
    Apr 24 13:46:44 tinkyx1 systemd[1]: zeek-worker@1.service: Failed with result 'core-dump'.
    Apr 24 13:46:45 tinkyx1 systemd[1]: zeek-worker@1.service: Scheduled restart job, restart counter is at 2.
    Apr 24 13:46:45 tinkyx1 systemd[1]: Starting zeek-worker@1.service - Zeek Worker 1...
    Apr 24 13:46:45 tinkyx1 systemd[1]: Started zeek-worker@1.service - Zeek Worker 1.
    Apr 24 13:46:45 tinkyx1 zeek-worker-1[2603512]: listening on eth1

This output shows zeek-worker@1 terminating due to a SIGABRT (here, ``kill -SIGABRT``
was used for demonstration purposes) and systemd automatically restarting the process
and reporting the current restart counter value. Use ``systemctl show zeek-worker@1``
to inspect this counter and various other details.

For debugging of crashes and coredump handling in general, we recommend installing
`systemd-coredump <https://www.freedesktop.org/software/systemd/man/latest/systemd-coredump.html>`_
and setting up ``/etc/systemd/coredump.conf`` as needed.

Inspecting coredumps is then possible with ``coredumpctl list``, ``coredumpctl debug``, etc:

.. code:: console

    # PAGER= coredumpctl info  | head -20
               PID: 2603455 (zeek)
               UID: 997 (zeek)
               GID: 995 (zeek)
            Signal: 6 (ABRT)
         Timestamp: Fri 2026-04-24 13:46:43 CEST (48min ago)
      Command Line: /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
        Executable: /opt/zeek/bin/zeek
     Control Group: /zeek.slice/zeek-workers.slice/zeek-worker@1.service
              Unit: zeek-worker@1.service
             Slice: zeek-workers.slice
           Boot ID: 0d20f470e7a9413d92f7324c27866992
        Machine ID: c9dbccfd439e43b598fa6153f5fa9e3e
          Hostname: tinkyx1
           Storage: /var/lib/systemd/coredump/core.zeek.997.0d20f470e7a9413d92f7324c27866992.2603455.1777031203000000.zst (present)
      Size on Disk: 10.4M
           Message: Process 2603455 (zeek) of user 997 dumped core.
    
                    Module libzstd.so.1 from deb libzstd-1.5.5+dfsg2-2build1.1.amd64
                    Module libsystemd.so.0 from deb systemd-255.4-1ubuntu8.15.amd64
                    Module libgcc_s.so.1 from deb gcc-14-14.2.0-4ubuntu2~24.04.1.amd64


.. _systemd_multiple_interfaces:


Multiple Interfaces
===================

.. versionadded:: 9.0

To monitor multiple interfaces, the ``zeek.conf`` file supports INI-style sections
where there is one section per interface. Each interface section name includes
a **tag** that's used in systemd's unit files, working directories, and also the
cluster node name. The tags used in the sample configuration below are ``eth1``
and ``eth2``.

When using the INI-style format, non-interface option must be placed into
the ``[zeek]`` section, conventionally put at the top.

.. code:: ini

    [zeek]
    loggers = 3
    proxies = 7

    [interface eth1]
    interface = af_packet::eth1
    workers = 4
    workers_cpu_list = 4-7
    worker_args = AF_Packet::fanout_id=42

    [interface eth2]
    interface = af_packet::eth2
    workers = 4
    workers_cpu_list = 8-11
    worker_args = AF_Packet::fanout_id=4711
    worker_env =
      LD_PRELOAD=/usr/local/lib/libjemalloc.so
      MALLOC_CONF=prof:true,prof_prefix:jeprof.out,prof_final:true,lg_prof_interval:26

With AF_PACKET, the respective workers have to use different fanout groups, so we need
to pass an explicit ``AF_Packet::fanout_id`` setting via the ``worker_args`` option.
This configuration also pins workers sequentially onto CPUs 4 through 11
and enables jemalloc profiling for all workers listening on eth2 via the
``worker_env`` option.

You will find that the worker unit names include the interface tags when
configured like this. I.e., instead of ``zeek-worker@1``, the first worker
for each interface is ``zeek-worker-eth1@1`` and ``zeek-worker-eth2@2``.
The ``CLUSTER_NODE`` and :zeek:see:`Cluster::node` values change accordingly:
``worker-1`` is ``worker-eth1-1`` and ``worker-eth2-1``. You can see these
values in the generated ``cluster-layout.zeek`` file.


Interface Templating
====================

The ``interface`` option supports templating. For example, selecting a
worker-specific Napatech stream for the interface looks as follows:

.. code:: ini

    [interface napatech]
    interface = napatech::${worker_index0}
    workers = 32

The ``${worker_index0}`` variable expands to the zero-based index of each worker
for this interface (0 through 31) and so every worker receives an individual
interface ``napatech::0``, ``napatech::1`` through ``napatech::31``. This can
also be useful to select a specific NETMAP pipe per worker.

.. code:: ini

    [interface eth1]
    interface = netmap::eth1{${worker_index0}
    workers = 32


Multi Host Walkthrough
======================

.. versionadded:: 9.0

.. note::

   Multi-host support using the zeek.conf is still being refined. We plan
   to finalize this towards Zeek 10.0. We welcome testing and feedback!

You can think of a host as an actual physical or virtual system, but it could
also be just a Linux container with its own network namespace. Any environment
with a dedicated networking stack and hostname can be considered a host in the
following paragraphs.

To create a Zeek cluster that spans multiple hosts, the format of the ``zeek.conf``
file does not change. However, you place the configuration files of all hosts of the
cluster at ``<PREFIX>/etc/zeek/cluster/<hostname>.zeek.conf`` on each host.
That means that every host has visibility into every other host's config. Use some
configuration management tool to keep the ``<PREFIX>/etc/zeek/cluster`` directories
in sync.

When no ``<PREFIX>/etc/zeek/zeek.conf`` file for a single-host configuration exists,
the ``zeek-systemd-generator`` will attempt to open ``<PREFIX>/etc/zeek/cluster/<hostname>.zeek.conf``
using the hostname of the system it is running on. If the file is found, it'll use
it to configure the appropriate systemd services using that specific config.
When executing the steps in the generated ``zeek-setup.service``, a ``cluster-layout.zeek``
containing all hosts and nodes is generated based on all of the ``*.zeek.conf`` files
within the ``<PREFIX>/etc/zeek/cluster`` directory.

This in an excerpt of the generated ``zeek-setup.service``, specifically the invocation
of the ``zeek-cluster-layout-generator`` tool.

.. code:: console

   # cat /run/systemd/generator/zeek-setup.service
   # Auto-generated, do not edit. Use drop-in files instead!
   ...
   [Service]
   Type=oneshot
   User=
   Group=
   WorkingDirectory=
   ExecStart=mkdir -p /usr/local/zeek/var/spool/zeek/generated-scripts
   ExecStart=/usr/local/zeek/bin/zeek-cluster-layout-generator -C /usr/local/zeek/etc/zeek/cluster -o /usr/local/zeek/var/spool/zeek/generated-scripts/cluster-layout.zeek


As of version 9.0, each host needs to be statically aware of all other hosts in
a cluster and able to resolve their IP addresses though the hostname as used in
the configuration filenames. Adding the required entries into ``/etc/hosts`` on
the respective systems is one way to achieve this, DNS would be another. Container
orchestrators usually allow to specify hostnames for containers or pods and
provide name resolution services as well.

You can point the ``zeek-cluster-layout-generator`` executable at a
``<PREFIX>/etc/zeek/cluster`` directory and inspect the generated layout.
If you do not specify a ``cluster_address`` option within the individual
``<hostname>.zeek.conf`` files, the generated ``cluster-layout.zeek`` file
contains extra script code to use Zeek's DNS functionality to lookup the
addresses of the involved hosts.

.. code:: console

    # zeek-cluster-layout-generator -C ./cluster/
    # Auto-generated by zeek-cluster-layout-generator
    ...

    const hosts: table[string] of Host &ordered &redef;

    redef Cluster::hosts += {
            ["c-mgr"] = [$ip=(blocking_lookup_hostname("c-mgr") as vector of addr)[0]],
            ["c-w-01"] = [$ip=(blocking_lookup_hostname("c-w-01") as vector of addr)[0]],
            ["c-w-02"] = [$ip=(blocking_lookup_hostname("c-w-02") as vector of addr)[0]],
    };

    redef Cluster::nodes += {
        ["manager"] = [$node_type=Cluster::MANAGER, $ip=hosts["c-mgr"]$ip, $p=27760/tcp, $metrics_port=9991/tcp],
        ["c-mgr-logger-1"] = [$node_type=Cluster::LOGGER, $ip=hosts["c-mgr"]$ip, $p=27761/tcp, $manager="manager", $metrics_port=9992/tcp],
    }

This means that each Zeek process will determine the addresses of all other
hosts in a cluster when loading the generated ``cluster-layout.zeek`` script
during startup. That's why it is important to have a functional ``/etc/hosts``
or DNS setup. Alternatively, set ``cluster_address`` to the host's address
in the respective ``<hostname>.zeek.conf``.


You can debug the resulting layout using Zeek itself:

.. code:: console

    # zeek -b <PREFIX>/var/spool/zeek/generated-scripts/cluster-layout.zeek -e 'print Cluster::nodes'
    {
    [c-w-02-worker-vxlan-4] = [node_type=Cluster::WORKER, ip=fd00:dead:beef::12, zone_id=, p=0/unknown, manager=manager, id=<uninitialized>, metrics_port=9994/tcp],
    [c-w-01-worker-vxlan-3] = [node_type=Cluster::WORKER, ip=fd00:dead:beef::11, zone_id=, p=0/unknown, manager=manager, id=<uninitialized>, metrics_port=9993/tcp],
    ...
    }

For a minimal three host cluster, where host ``c-mgr`` runs manager, 3 loggers,
2 proxies and the archiver and two hosts ``c-w-01`` and ``c-w-02`` that each
run 4 workers, listening on their eth1 interface using AF_PACKET, the following
configuration files are sufficient.


.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-mgr.zeek.conf
   [zeek]
   manager  = 1
   loggers  = 3
   proxies  = 2
   archiver = 1
   
   cluster_backend_args = misc/zeromq-multi-host-auto-setup

.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-w-01.zeek.conf
   [zeek]
   loggers  = 0
   proxies  = 0
   manager  = 0
   archiver = 0
   
   cluster_backend_args = misc/zeromq-multi-host-auto-setup
   
   [interface eth1]
   interface = af_packet::eth1
   workers = 4

.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-w-02.zeek.conf
   [zeek]
   loggers  = 0
   proxies  = 0
   manager  = 0
   archiver = 0
   
   cluster_backend_args = misc/zeromq-multi-host-auto-setup
   
   [interface eth1]
   interface = af_packet::eth1
   workers = 4


You synchronize the full ``<PREFIX>/etc/zeek/cluster`` directory with these
three files to all systems:

.. code:: console

    etc
    `-- zeek
        `-- cluster
            |-- c-mgr.zeek.conf
            |-- c-w-01.zeek.conf
            `-- c-w-02.zeek.conf


Then, run the following commands on each system to start all processes
on each of the hosts:

.. code:: console

    # systemctl daemon-reload
    # systemctl start zeek.target

On the ``c-mgr`` host, in ``<PREFIX>/var/spool/zeek/logger-{1,2,3}/cluster.log``,
you should see each of the Zeek nodes saying hello to each other node.

.. code:: console

   # for f in logger-*; do echo $f/cluster.log; head -3 $f/cluster.log; done
   logger-1/cluster.log
   {"ts":1784135106.521939,"node":"c-mgr-logger-1","message":"got hello from c-w-01-worker-eth1-1 (zeromq_c-w-01-worker-eth1-1_c-w-01_55_NfzaVa4ZA3BAmvqPx9)"}
   {"ts":1784135106.521939,"node":"c-mgr-logger-1","message":"got hello from c-w-01-worker-eth1-2 (zeromq_c-w-01-worker-eth1-2_c-w-01_56_NL4dCr4F5Hca3bxLKe)"}
   {"ts":1784135106.521939,"node":"c-mgr-logger-1","message":"got hello from manager (zeromq_manager_c-mgr_91_NIIFQV17DZe55r15Bd)"}
   logger-2/cluster.log
   {"ts":1784135106.446018,"node":"c-mgr-logger-2","message":"got hello from c-w-01-worker-eth1-3 (zeromq_c-w-01-worker-eth1-3_c-w-01_57_NIupbB37F2DKh2SDCg)"}
   {"ts":1784135106.446018,"node":"c-mgr-logger-2","message":"got hello from manager (zeromq_manager_c-mgr_91_NIIFQV17DZe55r15Bd)"}
   {"ts":1784135106.446263,"node":"c-mgr-logger-2","message":"got hello from c-mgr-logger-3 (zeromq_c-mgr-logger-3_c-mgr_90_Nig6uU2hdCFqaJr0c6)"}
   logger-3/cluster.log
   {"ts":1784135106.413847,"node":"c-mgr-logger-3","message":"got hello from c-w-01-worker-eth1-3 (zeromq_c-w-01-worker-eth1-3_c-w-01_57_NIupbB37F2DKh2SDCg)"}
   {"ts":1784135106.413847,"node":"c-mgr-logger-3","message":"got hello from manager (zeromq_manager_c-mgr_91_NIIFQV17DZe55r15Bd)"}
   {"ts":1784135106.445795,"node":"c-mgr-logger-3","message":"got hello from c-mgr-logger-2 (zeromq_c-mgr-logger-2_c-mgr_89_NAfhZd445aDO9AY8ed)"}

   # cat logger-*/cluster.log | jq .node | sort | uniq -c
     13 "c-mgr-logger-1"
     13 "c-mgr-logger-2"
     13 "c-mgr-logger-3"
     13 "c-mgr-proxy-1"
     13 "c-mgr-proxy-2"
     13 "c-w-01-worker-eth1-1"
     13 "c-w-01-worker-eth1-2"
     13 "c-w-01-worker-eth1-3"
     13 "c-w-01-worker-eth1-4"
     13 "c-w-02-worker-eth1-1"
     13 "c-w-02-worker-eth1-2"
     13 "c-w-02-worker-eth1-3"
     13 "c-w-02-worker-eth1-4"
     13 "manager"

Congratulations, you have a multi-host cluster running without ZeekControl.
