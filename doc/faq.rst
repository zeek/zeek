
==========================
Frequently Asked Questions
==========================

.. raw:: html

    <div class="faq">

.. contents::

Installation and Configuration
==============================

How can I tune my operating system for best capture performance?
----------------------------------------------------------------

Here are some pointers to more information:

* Fabian Schneider's research on `high performance packet capture
  <http://www.net.t-labs.tu-berlin.de/research/hppc>`_

* `NSMWiki <http://nsmwiki.org/Main_Page>`_ has page on
  *Collecting Data*.

* An `IMC 2010 paper
  <http://conferences.sigcomm.org/imc/2010/papers/p206.pdf>`_ by
  Lothar Braun et. al evaluates packet capture performance on
  commodity hardware

Are there any gotchas regarding interface configuration for live capture?  Or why might I be seeing abnormally large packets much greater than interface MTU?
-------------------------------------------------------------------------------------------------------------------------------------------------------------

Some NICs offload the reassembly of traffic into "superpackets" so that
fewer packets are then passed up the stack (e.g. "TCP segmentation
offload", or "generic segmentation offload").  The result is that the
capturing application will observe packets much larger than the MTU size
of the interface they were captured from and may also interfere with the
maximum packet capture length, ``snaplen``, so it's a good idea to disable
an interface's offloading features.

You can use the ``ethtool`` program on Linux to view and disable
offloading features of an interface.  See this page for more explicit
directions:

http://securityonion.blogspot.com/2011/10/when-is-full-packet-capture-not-full.html

What does an error message like ``internal error: NB-DNS error`` mean?
---------------------------------------------------------------------------------------------------------------------------------

That often means that DNS is not set up correctly on the system
running Bro. Try verifying from the command line that DNS lookups
work, e.g., ``host www.google.com``.

I am using OpenBSD and having problems installing Bro?
------------------------------------------------------

One potential issue is that the top-level Makefile may not work with
OpenBSD's default make program, in which case you can either install
the ``gmake`` package and use it instead or first change into the
``build/`` directory before doing either ``make`` or ``make install``
such that the CMake-generated Makefile's are used directly.

Generally, please note that we do not regularly test OpenBSD builds.
We appreciate any patches that improve Bro's support for this
platform.


Usage
=====

How can I identify backscatter?
-------------------------------

Identifying backscatter via connections labeled as ``OTH`` is not a reliable
means to detect backscatter. Backscatter is however visible by interpreting
the contents of the ``history`` field in the ``conn.log`` file. The basic idea
is to watch for connections that never had an initial ``SYN`` but started
instead with a ``SYN-ACK`` or ``RST`` (though this latter generally is just
discarded). Here are some history fields which provide backscatter examples:
``hAFf``, ``r``. Refer to the conn protocol analysis scripts to interpret the
individual character meanings in the history field.

Is there help for understanding Bro's resource consumption?
-----------------------------------------------------------

There are two scripts that collect statistics on resource usage:
``misc/stats.bro`` and ``misc/profiling.bro``. The former is quite
lightweight, while the latter should only be used for debugging.

How can I capture packets as an unprivileged user?
--------------------------------------------------

Normally, unprivileged users cannot capture packets from a network interface,
which means they would not be able to use Bro to read/analyze live traffic.
However, there are operating system specific ways to enable packet capture
permission for non-root users, which is worth doing in the context of using
Bro to monitor live traffic.

With Linux Capabilities
^^^^^^^^^^^^^^^^^^^^^^^

Fully implemented since Linux kernel 2.6.24, capabilities are a way of
parceling superuser privileges into distinct units.  Attach capabilities
required to capture packets to the ``bro`` executable file like this:

.. console::

   sudo setcap cap_net_raw,cap_net_admin=eip /path/to/bro

Now any unprivileged user should have the capability to capture packets
using Bro provided that they have the traditional file permissions to
read/execute the ``bro`` binary.

With BPF Devices
^^^^^^^^^^^^^^^^

Systems using Berkeley Packet Filter (BPF) (e.g. FreeBSD & Mac OS X)
can allow users with read access to a BPF device to capture packets from
it using libpcap.

* Example of manually changing BPF device permissions to allow users in
  the ``admin`` group to capture packets:

.. console::

   sudo chgrp admin /dev/bpf*
   sudo chmod g+r /dev/bpf*

* Example of configuring devfs to set permissions of BPF devices, adding
  entries to ``/etc/devfs.conf`` to grant ``admin`` group permission to
  capture packets:

.. console::

   sudo sh -c 'echo "own    bpf    root:admin" >> /etc/devfs.conf'
   sudo sh -c 'echo "perm   bpf    0640" >> /etc/devfs.conf'
   sudo service devfs restart

.. note:: As of Mac OS X 10.6, the BPF device is on devfs, but the used version
   of devfs isn't capable of setting the device permissions.  The permissions
   can be changed manually, but they will not survive a reboot.

Why isn't Bro producing the logs I expect? (A Note About Checksums)
-------------------------------------------------------------------

Normally, Bro's event engine will discard packets which don't have valid
checksums.  This can be a problem if one wants to analyze locally
generated/captured traffic on a system that offloads checksumming to the
network adapter.  In that case, all transmitted/captured packets will have
bad checksums because they haven't yet been calculated by the NIC, thus
such packets will not undergo analysis defined in Bro policy scripts as they
normally would.  Bad checksums in traces may also be a result of some packet
alteration tools.

Bro has two options to workaround such situations and ignore bad checksums:

1) The ``-C`` command line option to ``bro``.
2) An option called ``ignore_checksums`` that can be redefined at the
   policy script layer (e.g. in your ``$PREFIX/share/bro/site/local.bro``):

    .. code:: bro

      redef ignore_checksums = T;

The other alternative is to disable checksum offloading for your
network adapter, but this is not always possible or desirable.

.. raw:: html

    </div>
