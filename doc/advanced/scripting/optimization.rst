.. _zam:

===================
Script Optimization
===================

.. versionadded:: 7.0

.. note::

   ZAM has been available in Zeek for a number of releases, but as of Zeek 7
   it has matured to a point where we encourage regular users to explore it.

Introduction
============

The *Zeek Abstract Machine* (ZAM) is an optional script optimization engine
built into Zeek. Using ZAM changes the basic execution model for Zeek scripts in
an effort to gain higher performance.  Normally, Zeek parses scripts into
abstract syntax trees that it then executes by recursively interpreting each
node in a given tree.  With ZAM's script optimization, Zeek first compiles the
trees into a low-level form that it can then generally execute more efficiently.

To enable this feature, include ``-O ZAM`` on the command line.

How much faster will your scripts run?  There's no simple answer to that.  It
depends heavily on several factors:

* What proportion of the processing during execution is spent in the Zeek core's
  event engine, rather than executing scripts.  ZAM optimization doesn't help
  with event engine execution.

* What proportion of the script's processing is spent executing built-in
  functions (BiFs), i.e., functions callable from the script layer but
  implemented in native code.  ZAM optimization improves execution for some
  select, simple BiFs, like :zeek:id:`network_time`, but it doesn't help for
  complex ones.  It might well be that most of your script processing actually
  occurs in the underpinnings of the :ref:`logging framework
  <framework-logging>`, for example, and thus you won't see much improvement.

* Those two factors add up to gains very often on the order of only 10-15%,
  rather than something a lot more dramatic.

.. note::

   At startup, ZAM takes a few seconds to generate the low-level code for the
   loaded set of scripts, unless you're using Zeek's *bare mode* (via the
   ``-b`` command-line option), which loads only a minimal set of scripts. Keep
   this in mind when comparing Zeek runtimes, to ensure you're comparing only
   actual script execution time.

To isolate ZAM's code generation overhead when running Zeek on a pcap, simply
leave out the traffic. That is, turn this ...

.. code-block:: sh

   $ zcat 2009-M57-day11-18.trace.gz | zeek -O ZAM -r - <args>

into

.. code-block:: sh

   $ time zeek -O ZAM <args>

and, since Zeek drops into interactive mode when run without arguments,

.. code-block:: sh

   $ time zeek -O ZAM /dev/null

when there are none.

To determine the runtime after ZAM's code generation, you can measure the time
between :zeek:id:`zeek_init` and :zeek:id:`zeek_done` event handlers:

.. code-block:: zeek
   :caption: runtime.zeek

   global t0: time;

   event zeek_init()
       {
       t0 = current_time();
       }

   event zeek_done()
       {
       print current_time() - t0;
       }

Here's a quick example of ZAM's effect on Zeek's typical processing of a larger
packet capture, from one of our testsuites:

.. code-block:: sh

   $ zcat 2009-M57-day11-18.trace.gz | zeek -r - runtime.zeek
   14.0 secs 252.0 msecs 107.858658 usecs
   $ zcat 2009-M57-day11-18.trace.gz | zeek -O ZAM -r - runtime.zeek
   12.0 secs 345.0 msecs 857.990265 usecs

A roughly 13% improvement in runtime.

Other Optimization Features
===========================

You can tune various features of ZAM via additional options to ``-O``, see the
output of ``zeek -O help`` for details. For example, you can study the script
transformations ZAM applies, and use ZAM selectively in certain files (via
``--optimize-files``) or functions (via ``--optimize-funcs``).  Most users
won't need to use these.
