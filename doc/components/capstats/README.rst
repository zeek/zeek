..	-*- mode: rst-mode -*-
..
.. Version number is filled in automatically.
.. |version| replace:: 0.18

===============================================
capstats - A tool to get some NIC statistics.
===============================================

.. rst-class:: opening

    capstats is a small tool to collect statistics on the
    current load of a network interface, using either `libpcap
    <http://www.tcpdump.org>`_ or the native interface for `Endace's
    <http:///www.endace.com>`_. It reports statistics per time interval
    and/or for the tool's total run-time.

Download
--------

You can find the latest capstats release for download at
http://www.bro.org/download.

Capstats's git repository is located at `git://git.bro.org/capstats.git
<git://git.bro.org/capstats.git>`__. You can browse the repository
`here <http://git.bro.org/capstats.git>`__.

This document describes capstats |version|. See the ``CHANGES``
file for version history.


Output
------

Here's an example output with output in one-second intervals until
``CTRL-C`` is hit:

.. console::

    >capstats -i nve0 -I 1
    1186620936.890567 pkts=12747 kpps=12.6 kbytes=10807 mbps=87.5 nic_pkts=12822 nic_drops=0 u=960 t=11705 i=58 o=24 nonip=0
    1186620937.901490 pkts=13558 kpps=13.4 kbytes=11329 mbps=91.8 nic_pkts=13613 nic_drops=0 u=1795 t=24339 i=119 o=52 nonip=0
    1186620938.912399 pkts=14771 kpps=14.6 kbytes=13659 mbps=110.7 nic_pkts=14781 nic_drops=0 u=2626 t=38154 i=185 o=111 nonip=0
    1186620939.012446 pkts=1332 kpps=13.3 kbytes=1129 mbps=92.6 nic_pkts=1367 nic_drops=0 u=2715 t=39387 i=194 o=112 nonip=0
    === Total
    1186620939.012483 pkts=42408 kpps=13.5 kbytes=36925 mbps=96.5 nic_pkts=1 nic_drops=0 u=2715 t=39387 i=194 o=112 nonip=0

Each line starts with a timestamp and the other fields are:

    :pkts:
        Absolute number of packets seen by ``capstats`` during interval.

    :kpps:
        Number of packets per second.

    :kbytes:
        Absolute number of KBytes during interval.

    :mbps:
        Mbits/sec.

    :nic_pkts:
        Number of packets as reported by ``libpcap``'s ``pcap_stats()`` (may not match _pkts_)

    :nic_drops:
        Number of packet drops as reported by ``libpcap``'s ``pcap_stats()``.

    :u:
        Number of UDP packets.

    :t:
        Number of TCP packets.

    :i:
        Number of ICMP packets.

    :nonip:
        Number of non-IP packets.

Options
-------

A list of all options::

    capstats [Options] -i interface

       -i| --interface <interface>    Listen on interface
       -d| --dag                      Use native DAG API
       -f| --filter <filter>          BPF filter
       -I| --interval <secs>          Stats logging interval
       -l| --syslog                   Use syslog rather than print to stderr
       -n| --number <count>           Stop after outputting <number> intervals
       -N| --select                   Use select() for live pcap (for testing only)
       -p| --payload <n>              Verifies that packets' payloads consist
                                      entirely of bytes of the given value.
       -q| --quiet <count>            Suppress output, exit code indicates >= count
                                      packets received.
       -S| --size <size>              Verify packets to have given <size>
       -s| --snaplen <size>           Use pcap snaplen <size>
       -v| --version                  Print version and exit
       -w| --write <filename>         Write packets to file

Installation
------------

``capstats`` has been tested on Linux, FreeBSD, and MacOS. Please see
the ``INSTALL`` file for installation instructions.
