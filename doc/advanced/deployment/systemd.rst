
.. _deploy-systemd:

============================
Deploying Zeek using systemd
============================

.. versionadded:: 8.1

Zeek includes a `systemd generator <https://www.freedesktop.org/software/systemd/man/latest/systemd.generator.html>`_
that reads the ``<PREFIX>/etc/zeek/zeek.conf`` configuration file and instantiates systemd
unit files for the manager, logger, proxy and worker processes accordingly.
The generator is installed at ``<PREFIX>/bin/zeek-systemd-generator``.
systemd automatically runs generators during system startup, or on demand (see below).

.. note::

   ``zeek.conf`` file's focus is a system-level Zeek deployment tailored for
   appliance or container use cases. It presents an alternative to a
   :ref:`ZeekControl <cluster-configuration>` managed deployment.


Installation
============

After installing Zeek on your system, link Zeek's systemd generator into one
of the standard generator directories (create it if it does not exist):

.. code:: console

   # mkdir -p /etc/systemd/system-generators/
   # ln -s <PREFIX>/bin/zeek-systemd-generator /etc/systemd/system-generators/


Single Host Walkthrough
=======================

For a small Zeek deployment running two AF_PACKET worker processes on eth1,
one logger, one proxy, and the manager, the following configuration is sufficient:

.. code:: ini

    interface = af_packet::eth1
    workers = 2
    manager = 1
    loggers = 1
    proxies = 1

This minimal format is termed the section-less configuration style.
See the :ref:`systemd_multiple_interfaces` section for the more verbose INI-style
configuration that is required when you want to listen on multiple interfaces.

After running ``systemctl daemon-reload``, which executes ``zeek-systemd-generator``,
the generated unit files are found in the ``/run/systemd/generator`` directory of
the system:

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


.. note::

   Running ``systemctl daemon-reload`` does not provide immediate feedback about
   failures when running generators. If you do not see service unit files created,
   check for error messages using ``journalctl``.

   .. code:: console

       # journalctl -f
       Jul 27 17:10:31 tinkyx1 systemd[1]: Reloading...
       Jul 27 17:10:31 tinkyx1 /etc/systemd/system-generators/zeek-systemd-generator: config /opt/zeek-dev-prod/etc/zeek/zeek.conf is invalid
       Jul 27 17:10:31 tinkyx1 /etc/systemd/system-generators/zeek-systemd-generator: invalid workers value: '16x'
       Jul 27 17:10:31 tinkyx1 (sd-exec-[2365550]: /etc/systemd/system-generators/zeek-systemd-generator failed with exit status 1.

   You can also invoke the generator, optionally passing --config to validate the
   zeek.conf file beforehand. The units will be generated into directory provided
   as the last argument. If ``--config`` is not provided, it defaults to ``<PREFIX/etc/zeek/zeek.confg``.

   .. code:: console

       # <PREFIX>/bin/zeek-systemd-generator --config <PREFIX>/etc/zeek/zeek.conf /tmp/out
       config <PREFIX>/etc/zeek/zeek.conf is invalid
       invalid workers value: '1typo'

   If you have AppArmor or SELinux enabled, watch out for messages in the system
   logs; there may be extra configuration required to allow running the
   ``zeek-systemd-generator`` and ``zeek-cluster-layout-generator`` executables
   from where you installed them.


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


Individual Zeek processes are started as user ``zeek`` and group ``zeek``. This is
configurable with the ``user`` and ``group`` keys in the ``zeek.conf`` file.

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

This output shows ``zeek-worker@1`` terminating due to a SIGABRT (here, ``kill -SIGABRT``
was used for demonstration purposes) and systemd automatically restarting the process
and reporting the current restart counter value. Use ``systemctl show zeek-worker@1``
to inspect this counter and various other details.

For debugging of crashes and coredump handling in general, we recommend installing
`systemd-coredump <https://www.freedesktop.org/software/systemd/man/latest/systemd-coredump.html>`_
if your distro doesn't automatically do so and setting up ``/etc/systemd/coredump.conf`` as needed.

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


.. _systemd_multiple_interfaces:


Multiple Interfaces
===================

.. versionadded:: 9.0

To monitor multiple interfaces, the ``zeek.conf`` file supports INI-style sections
where there is one section per interface. Each interface section is named. The
name of the secution is used in systemd's unit files, working directories, and also
the cluster node name. The names used in the sample configuration below are ``eth1``
and ``eth2``, but could also be ``internal`` and ``external`` or anything
descriptive.

When using the INI-style format, place non-interface options into the ``[zeek]``
section, conventionally put at the top of the file:

.. code:: ini

    [zeek]
    manager = 1
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

You will find that the worker unit names include the section names when
configured like this. I.e., instead of ``zeek-worker@1``, the first worker
for each interface is ``zeek-worker-eth1@1`` and ``zeek-worker-eth2@2``.
The ``CLUSTER_NODE`` and :zeek:see:`Cluster::node` values change accordingly:
``worker-1`` is ``worker-eth1-1`` and ``worker-eth2-1``, respectively.
You can see these values in the generated ``cluster-layout.zeek`` file
at ``<PREFIX>/var/spool/zeek/generated-scripts/``.

.. note::

   You may wonder why there's even a section-less configuration style.
   It stems mostly from the initial ``zeek.conf`` version only supporting
   a single interface and not having sections. Further, working directories,
   unit names and the ``CLUSTER_NODE`` value for worker processes exclude
   the interface section name as an identifier to make them a bit shorter.

   The INI-style format works with a single interface just as well, so you
   can just use that exclusively and ignore the section-less style.


Worker Interface and Environment Templating
===========================================

For worker processes specifically, the ``interface`` and ``worker_env`` options
support templating. For example, selecting a worker-specific Napatech stream
for the interface can be expressed as follows:

.. code:: ini

    [interface napatech]
    interface = napatech::${worker_index0}
    workers = 32

The ``${worker_index0}`` variable expands to the zero-based index of each worker
for this interface (0 through 31) and so every worker receives an individual
interface ``napatech::0``, ``napatech::1`` through ``napatech::31``. This can
also be useful to select a specific NETMAP pipe per worker.


Templating also works for the single interface section-less configuration style:

.. code:: ini

    interface = netmap::eth1{${worker_index0}
    workers = 32
    manager = 1
    loggers = 2
    proxies = 4


Following is a list of the supported variables.

.. list-table:: Interpolation Variables

   * - ``${worker_index}``
     - The worker index starting at 1. Resets to 1 per interface section.

   * - ``${worker_index0}``
     - The worker index starting at 0. Resets to 0 per interface section.

   * - ``${host_worker_index}``
     - The worker index within the host. Starts at 1 and doesn't reset.

   * - ``${host_worker_index0}``
     - The worker index within the host. Starts at 0 and doesn't reset.

   * - ``${worker_cpu}``
     - The CPU a worker will be pinned on. Only available if ``workers_cpu_list`` is provided.
   * - ``${interface_section_name}``
     - The name part from the ``[interface <name>]`` section header.


To use templating in environment variables, use the same variable names
in the ``worker_env``:

.. code:: ini

    [zeek]
    manager = 1
    loggers = 3
    proxies = 7

    [interface eth1]
    interface = af_packet::${interface_section_name}
    workers = 8
    workers_cpu_list = 4-11
    worker_env =
      INTF=${interface_section_name}
      CPU=${worker_cpu}


Multi Host Walkthrough
======================

.. versionadded:: 9.0

.. note::

   Multi-host support using the zeek.conf is still being refined. We plan
   to finalize this towards Zeek 10.0. We welcome testing and feedback!

Two assumptions for running a multi-host Zeek cluster exist. First, all nodes
use compatible Zeek versions. This usually means deploying the exact same Zeek
build, plugins and packages everywhere. Second, name resolution on each system
allows to find the other hosts addresses.

To create a Zeek cluster that spans multiple hosts, the format of the ``zeek.conf``
file does not change. However, you place the configuration files of all hosts of the
cluster at ``<PREFIX>/etc/zeek/cluster/<hostname>.zeek.conf`` on each host.
That means that every host has visibility into every other host's configuration.
Use some configuration management tool to keep the ``<PREFIX>/etc/zeek/cluster``
directories in sync. In a container environment, a volume mount is a viable
alternative, too.

When no ``<PREFIX>/etc/zeek/zeek.conf`` file exists, the ``zeek-systemd-generator``
will attempt to open ``<PREFIX>/etc/zeek/cluster/<hostname>.zeek.conf`` using the
hostname of the system it is running on. If the file is found, it'll use it to configure
the appropriate systemd services. The ``zeek-cluster-layout-generator`` executable uses
the contents of ``<PREFIX>/etc/cluster`` to create the ``cluster-layout.zeek`` file.

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
   cluster_backend_args = misc/zeromq-multi-host-auto-setup
   
   [interface eth1]
   interface = af_packet::eth1
   workers = 4

.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-w-02.zeek.conf
   [zeek]
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


You successfully started up a multi-host Zeek cluster!


Archiver Support
================

Besides the Zeek processes participating in a cluster, support for log archiving is
enabled by default on hosts that run least one logger process or run the manager process:
This functionality is provided by `zeek-archiver <https://github.com/zeek/zeek-aux/tree/master/zeek-archiver>`_
and is visible earlier in the ``zeek.slice`` output:

.. code:: console

     CGroup: /zeek.slice
             ├─zeek-archiver.slice
             │ └─zeek-archiver.service
             │   └─2601102 /opt/zeek/bin/zeek-archiver /opt/zeek/var/spool/zeek/log-queue /opt/zeek/var/logs/zeek


To customize this functionality, you may set the ``archiver`` option in ``zeek.conf``
to ``0`` (disabled), ``1`` (enabled using ``zeek-archiver``),
or a path to a custom archiver executable that is expected to run continuously.
The latter may be used to run a log shipper that follows log files
created within the working directories of loggers.

The working directory for the archiver process is ``<PREFIX>/var/spool/zeek``
such that ``./logger-*/`` can be used to find the loggers' working directories,
or the ``./log-queue/`` directory into which loggers rotate their completed
logs by default.

``zeek-archiver``'s implementation is currently poll-based, listing the contents
of the ``log-queue`` directory in regular intervals, then compressing and rotating any
found logs into ``<PREFIX>/var/log/zeek/<date>/``. Further parameters to the archiver
can be given via ``archiver_args``.

.. code:: ini

   [zeek]
   ...
   archiver = 1
   # Enable verbose logging and reduce the polling interval from 30 to 3 seconds.
   archiver_args = -v -i 3


Using a custom archiver, like filebeat, looks as follows:

.. code:: ini

   [zeek]
   ...
   # Switch to using solely corelight/json-streaming-logs for logging.
   args = corelight/json-streaming-logs JSONStreaming::disable_default_logs=T

   # Switch to filebeat and cap resources a bit.
   archiver = /path/to/filebeat
   archiver_args = run -c /path/to/filebeat.yml --modules zeek
   archiver_cpu_set = 15,16
   archiver_memory_max = 2G

You'll need to adapt the logging logic of Zeek and provide a matching ``filebeat.yml``
file for this to work properly.


Process Capabilities
====================

This section is about Linux capabilities as they apply to Zeek processes. See the
`capabilities <https://man7.org/linux/man-pages/man7/capabilities.7.html>`_ manpage
for details. systemd supports the
`AmbientCapabilities and CapabilityBoundingSet <https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Capabilities>`_
settings. For usability reasons, systemd units for Zeek workers default the ``AmbientCapabilities``
to ``CAP_NET_RAW``. The ``CapabilityBoundingSet`` setting is left alone.

If you want to control process capabilities yourself, for example to switch to file-based
capabilities or add additional ambient capabilities, do so using systemd drop-in files.

Concretely, to modify the ``AmbientCapabilities`` for all Zeek worker processes,
place a drop-in unit file either into the ``zeek-worker@.service.d`` drop-in directory
when using the section-less format, or into a prefix drop-in directory named
``zeek-worker-.service.d`` when using the INI-like format. The latter is a bit magic:
systemd searches for drop-in directories using all dash-separated prefixes of a unit
name followed by ``.service.d``. Worker unit files have the ``zeek-worker-`` prefix
when using the INI-like format as for ``zeek-worker-eth1@.service`` and
``zeek-worker-eth2@.service`` with interface section names ``eth1`` and ``eth2``.

.. code:: console

    # cat /etc/systemd/system/zeek-worker-.service.d/10-drop-capabilities.conf
    [Service]
    # Remove all ambient capabilities from all worker processes.
    AmbientCapabilities=

    # cat /etc/systemd/system/zeek-worker-.service.d/10-more-capabilities.conf
    [Service]
    # Set capabilities for worker processes to add CAP_NET_ADMIN and
    # CAP_IPC_LOCK in addition to CAP_NET_RAW
    AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_IPC_LOCK

When unsetting ``AmbientCapabilities`` as on the first line, Zeek workers listening
on a real interface will fail to start because they are not permitted to read raw
packets anymore. If you have previously used file-based capabilities, you can
continue doing, either by ``setcap`` the executable during installation, or update
the ``zeek`` file capabilities by placing a drop-in file for the ``zeek-setup.service``
unit that adds an ``ExecStart`` command to run ``setcap``. This is shown below, ``setcap``
is used to add ``CAP_NET_RAW`` and ``CAP_NET_ADMIN`` to the effective and permissible
capability sets:

.. code:: console

    # cat /etc/systemd/system/zeek-setup.service.d/10-setcap-zeek.conf
    [Service]
    # Add file-based capabilities during zeek-setup.service execution
    ExecStart=/usr/sbin/setcap cap_net_raw,cap_net_admin+ep ./bin/zeek

The ``zeek-setup.service`` runs with a working directory of ``zeek.conf``'s ``base_dir``
option (PREFIX by default) and so using the relative path to ``./bin/zeek`` works out.
Note that if you do this, the manager, logger and proxy processes will also receive
``CAP_NET_RAW`` and ``CAP_NET_ADMIN`` capabilities, even though they likely do not need
those.

To verify the final capabilities of a running process, find its PID via
``systemctl status zeek.slice`` and use ``getpcaps`` on it:

.. code:: console

   # getpcaps 129003
   129003: cap_net_admin,cap_net_raw=ep


Cluster Layout Notes
====================

.. note::

   Some of the current requirements around the static ``cluster-layout.zeek``
   file are historic and there's ideas to relax some of them.

As of version 9.0, each host needs to be statically aware of all other hosts in
a cluster and able to resolve their IP addresses though the hostname as used in
the configuration filenames. Adding the required entries into ``/etc/hosts`` on
the respective systems is one way to achieve this, DNS is another. Container
orchestrators usually allow specifying hostnames for containers or pods,
and provide name resolution services as well.

The ``zeek-cluster-layout-generator`` executable creates the contents
of a ``cluster-layout.zeek`` file.

You can point the ``zeek-cluster-layout-generator`` executable at a
``<PREFIX>/etc/zeek/cluster`` directory and inspect the generated layout
for a multi-host Zeek cluster.
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
or DNS setup.

If you want to control IP addresses and cluster node prefixes used,
set ``cluster_address`` and ``cluster_node_prefix`` explicitly for every
host as in the following example. Setting ``cluster_node_prefix`` to an
empty string unsets the prefix for that host.

.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-mgr.zeek.conf
   [zeek]
   manager  = 1
   loggers  = 3
   proxies  = 2
   archiver = 1
   
   cluster_node_prefix =
   cluster_address = 10.0.0.1
   cluster_backend_args = misc/zeromq-multi-host-auto-setup

.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-w-01.zeek.conf
   [zeek]
   cluster_node_prefix = worker-01
   cluster_address = 10.0.0.2
   cluster_backend_args = misc/zeromq-multi-host-auto-setup
   
   [interface eth1]
   interface = af_packet::eth1
   workers = 4

.. code:: ini

   # <PREFIX>/etc/zeek/cluster/c-w-02.zeek.conf
   [zeek]
   cluster_node_prefix = worker-02
   cluster_address = 10.0.0.3
   cluster_backend_args = misc/zeromq-multi-host-auto-setup
   
   [interface eth1]
   interface = af_packet::eth1
   workers = 4


If you want to use your own completely-custom ``cluster-layout.zeek`` file,
it is possible to set the ``cluster_layout`` option to a path. The generated
``zeek-setup.service`` will copy the file into ``<PREFIX>/var/spool/zeek/generated-scripts``
instead of dynamically creating a layout.

.. code:: ini

   [zeek]
   cluster_layout = /path/to/custom-cluster-layout.zeek
   cluster_backend_args = misc/zeromq-multi-host-auto-setup
   ...

Cluster Layout Debugging
------------------------

You can debug the resulting layout using Zeek itself:

.. code:: console

    # zeek -b <PREFIX>/var/spool/zeek/generated-scripts/cluster-layout.zeek -e 'print Cluster::nodes'
    {
    [c-w-02-worker-vxlan-4] = [node_type=Cluster::WORKER, ip=fd00:dead:beef::12, zone_id=, p=0/unknown, manager=manager, id=<uninitialized>, metrics_port=9994/tcp],
    [c-w-01-worker-vxlan-3] = [node_type=Cluster::WORKER, ip=fd00:dead:beef::11, zone_id=, p=0/unknown, manager=manager, id=<uninitialized>, metrics_port=9993/tcp],
    ...
    }

For the single-host case, the invocation of ``zeek-cluster-layout-generator`` contains
explicit logger, proxy, worker counts rather than reading ``zeek.conf`` files:

.. code:: console

    # zeek-cluster-layout-generator -W 1 -a 192.168.0.1 -m 0 -p 5000
    # Auto-generated by zeek-cluster-layout-generator

    redef Cluster::nodes += {
        ["manager"] = [$node_type=Cluster::MANAGER, $ip=192.168.0.1, $p=5000/tcp, $metrics_port=0/tcp],
        ["logger-1"] = [$node_type=Cluster::LOGGER, $ip=192.168.0.1, $p=5001/tcp, $manager="manager", $metrics_port=0/tcp],
        ["proxy-1"] = [$node_type=Cluster::PROXY, $ip=192.168.0.1, $p=5002/tcp, $manager="manager", $metrics_port=0/tcp],
        ["worker-1"] = [$node_type=Cluster::WORKER, $ip=192.168.0.1, $manager="manager", $metrics_port=0/tcp],
    };
    ...


You can use the ``zeek-cluster-layout-generator`` executable in non-Linux
and non-systemd environments as well.
