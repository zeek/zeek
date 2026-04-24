
.. _deploy-systemd:

============================
Deploying Zeek using systemd
============================

.. versionadded:: 8.1.0

Zeek includes a `systemd generator <https://www.freedesktop.org/software/systemd/man/latest/systemd.generator.html>`_
that reads the ``<PREFIX>/etc/zeek/zeek.conf`` configuration file and instantiates systemd
unit files for the manager, logger, proxy and worker processes accordingly.
The generator is installed at ``<PREFIX>/bin/zeek-systemd-generator``.

.. note::

   The ``zeek.conf`` file's focus is currently an opinionated single node multi-interface
   Zeek deployment. Multi-node support is planned for the future.


Installation
============

To use the generator, link it into one of systemd's generator directories:

.. code:: console

   # ln -s <PREFIX>/bin/zeek-systemd-generator /etc/systemd/system-generators/


Walkthrough
===========

For a minimal and basic Zeek deployment listening on eth1 with 2 workers using
AF_PACKET for flow-balancing on Linux, the following configuration is sufficient:

.. code:: ini

    interface = af_packet::eth1
    workers = 2

This is also termed the section-less configuration style. See the :ref:`systemd_multiple_interfaces`
section for the INI configuration style.

After running ``systemctl daemon-reload``, the resulting unit files are
located in the ``/run/systemd/generator`` directory where they can be inspected:

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
using ``--reverse`` or ``--follow``:

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

This output shows zeek-worker@1 terminating due to a SIGABRT (``kill -SIGABRT`` was used)
and systemd restarting it and reporting the current restart counter value. This counter
and much more information about the unit can be queried using ``systemctl show zeek-worker@1``.

For debugging of crashes and coredump handling in general, we recommend installing
the ``systemd-coredump`` package and configuring ``/etc/systemd/coredump.conf`` accordingly.
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

To monitor multiple interfaces, the ``zeek.conf`` file supports INI-style sections
where there is one section per interface. Each interface section name includes
a "tag" that's used in systemd's unit files, working directories, and also the
cluster node name. The tags below are ``eth1`` and ``eth2``.

There is also a ``[zeek]`` section that holds non-interface related configuration.
For example, the number of loggers and proxies.

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
to pass an explicit ``AF_Packet::fanout_id`` setting via ``worker_args``.
This configuration also pins workers sequentially onto CPUs 4 through 11
and enables jemalloc profiling for all workers listening on eth2.


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

Summary
=======

This was a quick intro how to deploy Zeek using ``zeek.conf`` and systemd.
The default ``zeek.conf`` file has extensive documentation and details about
the options used here.
