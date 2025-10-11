# zeek-systemd-generator

This directory contains code for a [systemd generator](https://www.freedesktop.org/software/systemd/man/latest/systemd.generator.html)
to run a single-node Zeek deployment on modern Linux distributions.

## Installation

Zeek's default build on Linux contains a ``zeek-systemd-generator`` executable
in its ``bin/`` directory. To enable the generator, link it into one of systemd's
generator directories:

    $ ln -s /usr/local/zeek/bin/zeek-systemd-generator /etc/systemd/system-generators/

After that, modify ``<PREFIX>/etc/default/zeek`` as needed. Particularly, set
the ``interface`` key:

    interface = af_packet::eth0

    proxies = 1
    loggers = 1
    workers = 4
    ...

Thereafter, run the following commands:

    $ systemctl daemon-reload
    $ systemctl start zeek.target

To verify the ``zeek-systemd-generator`` produces the expected unit files for
a given configuration, invoke it with a single testing directory:

    $ mkdir test-directory
    $ <PREFIX>/bin/zeek-systemd-generator test-directory

``zeek-systemd-generator`` will attempt to read configuration files at
``<PREFIX>/etc/default/zeek`` and ``/etc/default/zeek``. It's possible
to set the environment variable ``CONFIG_FILE`` to use a different path.

## Monitoring

Use ``journalctl`` or ``systemctl status`` with the individual unit names
like ``zeek-manager.service`` or ``zeek-worker@1.service``.
