
.. _deploy-systemd:

============================
Deploying Zeek using systemd
============================

.. versionadded:: 8.1.0

Zeek includes a `systemd generator <https://www.freedesktop.org/software/systemd/man/latest/systemd.generator.html>`_
that reads ``<PREFIX>/etc/zeek/zeek.conf`` and instantiates systemd unit files
for the manager, logger, proxy and worker processes. This generator installed
at ``<PREFIX>/bin/zeek-systemd-generator``.

.. note::

   The ``zeek.conf`` file's focus is currently an opinonated single node multi-interface
   Zeek deployment. Multi-node support may be added in the future.


Installation
============

To use the generator, you need to link it into one of systemd's generator directories.

.. code:: console

   # ln -s <PREFIX>/bin/zeek-systemd-generator /etc/systemd/system-generators/


Examples
========

For a minimal Zeek deployment, listening on eth1 with 4 workers using AF_PACKET
for flow balancing, the following configuration is sufficient.

.. code:: ini

    # <PREFIX>/etc/zeek/zeek.conf
    interface = af_packet::eth1
    workers   = 4

Run ``systemctl daemon-reload`` to render the unit files.
Inspect the result in ``/run/systemd/generator`` if wanted:

.. code:: console

    # ls -lha /run/systemd/generator/zeek* | head
    -rw-r--r-- 1 root root  540 Apr 20 20:16 /run/systemd/generator/zeek-archiver.service
    -rw-r--r-- 1 root root 1,1K Apr 20 20:16 /run/systemd/generator/zeek-interface-1-worker@.service
    -rw-r--r-- 1 root root 1,1K Apr 20 20:16 /run/systemd/generator/zeek-interface-2-worker@.service
    -rw-r--r-- 1 root root  925 Apr 20 20:16 /run/systemd/generator/zeek-logger@.service
    -rw-r--r-- 1 root root  919 Apr 20 20:16 /run/systemd/generator/zeek-manager.service
    -rw-r--r-- 1 root root  924 Apr 20 20:16 /run/systemd/generator/zeek-proxy@.service
    -rw-r--r-- 1 root root 3,2K Apr 20 20:16 /run/systemd/generator/zeek-setup.service
    -rw-r--r-- 1 root root  160 Apr 20 20:16 /run/systemd/generator/zeek.target

Start Zeek using:

.. code:: console

    # systemctl start zeek.target


The previous configuration runs one manager, one logger and one proxy
process by default. These and be configured by explicitly setting the
``loggers`` and ``proxies`` keys before the first ``interface``:

.. code:: ini

    # <PREFIX>/etc/zeek/zeek.conf
    loggers   = 3
    proxies   = 7

    interface = afpacket::eth1
    workers   = 32

For listening on two interfaces, use a second ``interface`` key to start
a new interface configuration. With AF_PACKET, the respective workers have
to use different fanout groups, so we need to pass an explicit
``AF_Packet::fanout_id`` setting. All workers of an interface configuration
share the same ``worker_args``.

This example also shows how to pin workers using the ``workers_cpu_list`` options
and configuring NUMA affinity for individual worker processes.

.. code:: ini

    # <PREFIX>/etc/zeek/zeek.conf
    loggers   = 3
    proxies   = 7

    # eth1 configuration
    interface          = af_packet::eth1
    worker_args        = AF_Packet::fanout_id=42
    workers            = 4
    workers_cpu_list   = 1-4
    worker_numa_policy = local

    # eth2 configuration
    interface          = af_packet::eth2
    worker_args        = AF_Packet::fanout_id=4711
    workers            = 4
    workers_cpu_list   = 17-21
    worker_numa_policy = local

To introspect which processes have been launched, use ``systemd-cgtop`` with
the ``zeek.slice``:

.. code:: console

    # systemctl daemon-reload
    # systemctl start zeek.target

    # systemctl status zeek.slice
    ● zeek.slice - Slice /zeek
         Loaded: loaded
         Active: active since Mon 2026-04-20 17:40:28 CEST; 2h 36min ago
          Tasks: 326
         Memory: 1.7G (peak: 2.5G swap: 0B swap peak: 301.7M)
            CPU: 43min 32.522s
         CGroup: /zeek.slice
                 ├─zeek-archiver.slice
                 │ └─zeek-archiver.service
                 │   └─227951 /opt/zeek/bin/zeek-archiver /opt/zeek/var/spool/zeek/log-queue /opt/zeek/var/logs/zeek
                 ├─zeek-loggers.slice
                 │ ├─zeek-logger@1.service
                 │ │ └─227952 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ ├─zeek-logger@2.service
                 │ │ └─227953 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ └─zeek-logger@3.service
                 │   └─227954 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 ├─zeek-manager.slice
                 │ └─zeek-manager.service
                 │   └─227955 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 ├─zeek-proxies.slice
                 │ ├─zeek-proxy@1.service
                 │ │ └─227975 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ ├─zeek-proxy@2.service
                 │ │ └─227976 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ ├─zeek-proxy@3.service
                 │ │ └─227978 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ ├─zeek-proxy@4.service
                 │ │ └─227956 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ ├─zeek-proxy@5.service
                 │ │ └─227957 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ ├─zeek-proxy@6.service
                 │ │ └─227958 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 │ └─zeek-proxy@7.service
                 │   └─227959 /opt/zeek/bin/zeek policy/misc/systemd-generator local frameworks/cluster/backend/zeromq
                 └─zeek-workers.slice
                   ├─zeek-interface-1-worker@1.service
                   │ └─227991 /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local AF_Packet::fanout_id=42 frameworks/cluster/backend/zeromq
                   ├─zeek-interface-1-worker@2.service
                   │ └─227994 /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local AF_Packet::fanout_id=42 frameworks/cluster/backend/zeromq
                   ├─zeek-interface-1-worker@3.service
                   │ └─227987 /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local AF_Packet::fanout_id=42 frameworks/cluster/backend/zeromq
                   ├─zeek-interface-1-worker@4.service
                   │ └─227965 /opt/zeek/bin/zeek -i af_packet::eth1 policy/misc/systemd-generator local AF_Packet::fanout_id=42 frameworks/cluster/backend/zeromq
                   ├─zeek-interface-2-worker@5.service
                   │ └─227968 /opt/zeek/bin/zeek -i af_packet::eth2 policy/misc/systemd-generator local AF_Packet::fanout_id=4711 frameworks/cluster/backend/zeromq
                   ├─zeek-interface-2-worker@6.service
                   │ └─227984 /opt/zeek/bin/zeek -i af_packet::eth2 policy/misc/systemd-generator local AF_Packet::fanout_id=4711 frameworks/cluster/backend/zeromq
                   ├─zeek-interface-2-worker@7.service
                   │ └─227970 /opt/zeek/bin/zeek -i af_packet::eth2 policy/misc/systemd-generator local AF_Packet::fanout_id=4711 frameworks/cluster/backend/zeromq
                   └─zeek-interface-2-worker@8.service
                     └─227972 /opt/zeek/bin/zeek -i af_packet::eth2 policy/misc/systemd-generator local AF_Packet::fanout_id=4711 frameworks/cluster/backend/zeromq
