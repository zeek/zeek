# zeek-systemd-generator

This directory contains code for a [systemd generator](https://www.freedesktop.org/software/systemd/man/latest/systemd.generator.html)
to run a single-node Zeek deployment on modern Linux distributions.

## Installation

Zeek's default installation on Linux contains a ``zeek-systemd-generator`` executable
in its ``bin/`` directory. To enable the generator, link it into one of systemd's
generator directories:

    $ ln -s <PREFIX>/bin/zeek-systemd-generator /etc/systemd/system-generators/

After that, modify ``<PREFIX>/etc/zeek/zeek.conf`` as needed. Particularly, set
the ``interface`` key to a non-empty value.

    interface = af_packet::eth0

    proxies = 1
    loggers = 1
    workers = 4
    ...

Thereafter, run the following commands:

    $ systemctl daemon-reload
    $ systemctl start zeek.target

See the example ``zeek.conf`` file in the distribution for documentation
about the supported configuration keys.

## Testing

To verify the ``zeek-systemd-generator`` produces the expected unit files for
a given configuration, invoke it with a single testing directory:

    $ mkdir test-directory
    $ <PREFIX>/bin/zeek-systemd-generator test-directory

``zeek-systemd-generator`` will attempt to read the configuration file at
``<PREFIX>/etc/zeek/zeek.conf``. It's possible to use ``--config`` to
override the configuration file lookup for testing.

## Monitoring

Use ``journalctl`` or ``systemctl status`` with the individual unit names
like ``zeek-manager.service`` or ``zeek-worker@1.service``.
