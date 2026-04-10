.. _install-rust: https://rust-lang.org/tools/install/ 
.. _xdp-tools: https://github.com/xdp-project/xdp-tools/
.. _xdp-loader: https://github.com/xdp-project/xdp-tools/blob/main/xdp-loader/README.org

.. _xdp_shunt:

=================
Shunting with XDP
=================

.. note::

   This is experimental! Because of that, the shunter does not ship with
   Zeek by default and must be enabled with a build manually. This document
   will explain how to enable it and how to use it.

There is a lot of network traffic that Zeek isn't particularly equipped to
do much with. Consider encrypted traffic: normally, Zeek won't do much with
the provided information. But, Zeek may spend significant amounts of time
processing it. There could also be huge "elephant" flows that take up a
large part of a worker's resources. After a certain point, Zeek will get
more information by processing more traffic from other sources. In order
to let Zeek do that, we may simply drop the traffic after we designate
the flow as "not interesting" via *shunting*.

There are many mechanisms that you can use to shunt. One is already in Zeek:
the :ref:`framework-netcontrol`. That gives the user a general way to shunt
traffic with different plugins.

.. note::

   The XDP shunter does not currently implement a NetControl plugin.

XDP provides a generic way for Linux hosts to shunt traffic before Zeek ever
sees it. XDP stands for eXpress Data Path and is used to run programs on
code before userspace programs (like Zeek) ever see the traffic. We use this
in order to drop traffic very soon in the network stack, often right after
the network card processes the data.

Building
========

The XDP-based shunter is currently experimental, so it is disabled by
default. Thus, you must :ref:`build Zeek from source <building-from-source>`.
You will also need a couple of extra dependencies for XDP programs. You can
install these with ``apt`` as follows:

.. code-block:: console

   $ sudo apt install bpftool libxdp-dev clang

The shunter also requires Rust for the loader. We recommend
`installing Rust <install-rust_>`_ with ``rustup``.

Then, use the same ``./configure`` command as when building from source, but
add ``--enable-xdp-shunter``:

.. code-block:: console

   $ ./configure --enable-xdp-shunter

Finally, you can use ``make`` in the ``build/`` directory to build, or
however you plan on building Zeek (possibly with ``ninja``).

Standalone Usage
================

By default, the XDP shunter is not loaded. Instead, you must load a policy
script in order to enable it. Add this to a test script:

.. literalinclude:: xdp-shunt/basic.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

By default, the XDP program will not load into the kernel. Instead, the
shunter would attach to the existing maps from a loaded XDP program. Here,
we override this behavior by setting ``XDP::start_new_xdp = T``. This also
means that the shunting XDP program will be unloaded when the Zeek process
exits.

There are a couple of XDP shunting programs that load by default, in
``frameworks/xdp-shunt/bulk.zeek`` and ``frameworks/xdp-shunt/ssl.zeek``.
The former will shunt "elephant" flows with a configurable max size before
shunting begins, the latter will shunt SSL connections after it is
established.

Now, run the test program (replace ``veth-test`` with your interface):

.. code:: console

   $ sudo zeek test.zeek -C -i veth-test

You can check to see if the XDP program was loaded on the interface with
``xdp-loader`` from `xdp-tools`_:

.. code:: console

   $ sudo xdp-loader status
   CURRENT XDP PROGRAM STATUS:

   Interface        Prio  Program name      Mode     ID   Tag               Chain actions
   --------------------------------------------------------------------------------------
   <...>
   veth-test              xdp_filter        native   334  3c363462723ee853

Now, if that interface is getting live traffic, the program should print any
connections that get shunted and unshunted. You can also verify that it is
shunting connections with the builtin ``zeek-xdp-loader`` (only enabled when
you build zeek with ``--enable-xdp-shunter``):

.. code:: console

   $ sudo ~/.local/zeek/bin/zeek-xdp-loader count
   Found 12 entries in map.

That means that 12 flows are shunted. If none are shunted, make sure the
interface is seeing traffic, and make sure the traffic it sees would be
shunted.

.. note::

   Each command so far has used ``sudo``. This is the most foolproof way
   to use XDP programs, since they are loaded in the kernel. Here, Zeek
   needs to load the XDP program, so we use ``sudo``. However, Zeek does not
   need to start the XDP program. If you load the XDP program, then ``chmod``
   the BPF map directories, ``zeek`` will run without permissions, like:

   .. code:: console

      $ sudo chmod 755 /sys/fs/bpf
      $ sudo xdp-loader load <interface> build/src/xdp_shunt/bpf/filter.o -p /sys/fs/bpf/zeek
      $ sudo chmod 755 /sys/fs/bpf/zeek
      $ sudo chmod 666 /sys/fs/bpf/zeek/*

   For now, we will simply use ``sudo``, since it may be difficult to load
   the XDP programs for demonstration without it. However, it is not necessary
   for the Zeek process once running.

Clusters
========

For clusters, the XDP shunter has a ``zeekctl`` plugin to load the XDP program
*before* starting any Zeek processes. This is necessary since clusters may
run multiple Zeek processes on one interface. It also decouples the XDP
program from Zeek itself, so all Zeek does is add and remove elements from
a map. We saw before how that means Zeek does not need to run as root.

In fact, clusters may be the simplest way to run the XDP shunter. Just set
``xdp.enabled`` in ``zeekctl.cfg``:

.. code::

   xdp.enabled = True

And that is all. You may have to adjust a couple of other options, such as
map sizes (depending on how much traffic you give to Zeek) and the "attach
mode" of XDP (which we will discuss later).

Setting ``xdp.enabled`` implies loading the XDP policy script, so that should
be all you need. Now just deploy the cluster:

.. code:: console

   $ zeekctl deploy

Then Zeek should shunt traffic via XDP! You can ensure the XDP program is
loaded with ``xdp-loader`` as before, or check how many flows are shunted
with ``zeek-xdp-loader``.

Custom Shunting
===============

While some traffic is shunted out of the box, you can get a lot more mileage
by choosing what traffic to shunt. This may be particularly busy protocols
on your network that have little security value, or simply shunting
particular known subnets with particular protocols.

First, we will see how the SSL shunting script works. This is the entirety of
its logic:

.. literalinclude:: xdp-shunt/shunt-ssl.zeek
   :language: zeek
   :tab-width: 4

All of this to say: shunting is simple! It is just one function call with
the connection, then that connection will not see traffic.

Now, you can just add this ``shunt`` call whenever you want to shunt. But,
there is an extra variable you can use to control even builtin shunting
logic: the ``XDP::shunting`` hook. This is checked before shunting any
connection, so we can use it to ensure only internal traffic is shunted
(for example). Here's an example:

.. literalinclude:: xdp-shunt/shunt-internal-only.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

This program will print when a shunt was vetoed (by breaking from the hook)
and when it was shunted from the ``shunted_conn`` event. You can see that
you can have arbitrary logic in the hook in order to *prevent* shunting, as
well as to trigger shunting.

Loading XDP
===========

The XDP program itself loads in the kernel. While Zeek mostly abstracts this,
it may be important for some deployments, such as users who don't have an out
of the box cluster solution. Feel free to browse the `xdp-loader`_
documentation for more information about loading XDP programs in general.

The most important consideration is the XDP *mode*. This dictates how the XDP
program is loaded in kernel. The most generic option is SKB mode. This can
work regardless of your network interface controller (NIC) and its drivers.
But, because it's generic, it is also the slowest. Now, you may still get
faster execution with SKB mode than many other solutions (it's still early!)
but it's not the preferred solution.

You will most likely use native XDP mode. This means that the NIC driver
implemented XDP, so the shunting program runs as early as possible in the
kernel.

There is a chance with certain smart NICs that it implements offload mode.
This means that the XDP program actually runs on the NIC (even earlier!).
This is relegated to very particular cards, but it's quite powerful. We have
not yet tested shunting with offload XDP mode.

XDP Considerations
++++++++++++++++++

Remember that the XDP program runs very early in the kernel. Because of this,
you must consider certain limitations with memory pages. One such
consideration is with maximum transmission unit (MTU) sizes. Certain
environments use jumbo frames (like 9000 bytes). Cases like this require
special handling in XDP.

.. note::

   We have implemented support for jumbo frames in XDP, but it seems broken
   in certain environments. The MTU size says it is too large! If you use
   jumbo frames and want to try it, we would love to hear from you.

If testing this locally, try to use a virtual ethernet pair or some other
method to get traffic on a different interface from your internet connection.
You may end up shunting traffic that is actively used to communicate on the
internet. If you don't know how to unload the XDP program, that might be a
problem! For that reason, here is how you unload all XDP programs on a
network interface:

.. code:: console

   $ sudo xdp-loader unload <interface> --all
