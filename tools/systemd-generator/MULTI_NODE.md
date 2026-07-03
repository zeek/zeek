# Multi node clusters with systemd

For a single host, Zeek's configuration is at ``<PREFIX>/etc/zeek/zeek.conf``.
It describes the processes and interfaces to run on this system. There's only
a single system involved.

## Static Multi-Node Setup

For a static multi-host setup, the configuration files for all physical or virtual
hosts, or individual containers are placed into ``<PREFIX>/etc/zeek/cluster/``.

For static clusters, the system's hostname is important. The naming scheme of
configuration files in this directory is ``<hostname>.zeek.conf``.
The ``zeek-systemd-generator`` will read ``/etc/hostname`` and check for the
existence of a file in ``<PREFIX>/etc/zeek/cluster/<hostname>.zeek.conf`` and
use it for the local configuration.


Requirement 1: Proper hostname configuration of VM or containers.


Directory layout
