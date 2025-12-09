.. _ZeekControl documentation: https://github.com/zeek/zeekctl
.. _FAQ: https://zeek.org/faq/
.. _Get Zeek: https://zeek.org/get-zeek/
.. _Zeek source code: https://github.com/zeek/zeek
.. _gzip: https://www.gzip.org/

.. _quickstart:

=================
Quick Start Guide
=================

Zeek is a network traffic analyzer. Zeek works on most modern Unix-based
systems and does not require custom hardware. See :doc:`install` in order to
install from pre-built binary packages, or :doc:`building-from-source` in order
to build Zeek from source.

We will first analyze previously captured network traffic from a ``pcap`` file -
:download:`quickstart.pcap <traces/quickstart.pcap>`. Later, we will use Zeek to
monitor live traffic. Each section builds on the previous section.

Running Zeek
============

Open a terminal, navigate to a clean directory, and run zeek on the
:file:`quickstart.pcap` file:

   .. code-block:: console

     zeek -r quickstart.pcap LogAscii::use_json=T

Zeek should not produce any output, but it will create a few log files:

 * :file:`conn.log`
 * :file:`http.log`
 * :file:`weird.log`

The connection log, or :file:`conn.log`, records each connection that Zeek
detects. The created :file:`conn.log` has two entries. Here are those entries
(some fields are cut for brevity with "..."):

   .. code-block:: console


     {
        "ts": 1747147647.668533,
        "uid": "CmgO6f3ddanrRjiCoc",
        ...
     },
     {
        "ts": 1747147654.27566,
        "uid": "CQuwSY2FD0NsLn9CJj",
        ...
     }

Now to find out more about both of these connections. Looking at the HTTP log,
it also has two entries. Take note of the ``uid`` field, short for unique
identifier. You can use that field to pivot from :file:`conn.log` to
:file:`http.log` - the UIDs in one should correlate to entries in the other. The
abbreviated logs for these two requests are:

   .. code-block:: console

     {
         "ts": 1747147647.702181,
         "uid": "CmgO6f3ddanrRjiCoc",
         "method": "GET",
         "host": "zeek.org",
         "uri": "/",
         ...
     },
     {
         "ts": 1747147654.311012,
         "uid": "CQuwSY2FD0NsLn9CJj",
         "method": "WEIRD",
         "host": "zeek.org",
         "uri": "/",
         ...
     }

The first entry is a simple ``GET`` request to zeek.org. The second entry used
a non-standard HTTP method: ``WEIRD``. Zeek also records unusual or unexpected
behavior in :file:`weird.log`, such as this invalid HTTP method. Now, pivot
from :file:`http.log` to :file:`weird.log`, where there will be a "weird" for
the second entry's UID:

   .. code-block:: console

     {
       "ts": 1747147654.311012,
       "uid": "CQuwSY2FD0NsLn9CJj",
       "name": "unknown_HTTP_method",
       "addl": "WEIRD",
       ...
     }

The UID for this entry is the same as the second entry in :file:`conn.log` and
:file:`http.log`. Therefore, there were two HTTP requests, one with a ``GET``
request and one with a ``WEIRD`` request. The ``WEIRD`` request was rightfully
classified as a "weird" by Zeek.

More information on the various logs and what they report can be found in the
:doc:`logs/index` section. More information on working with logs can be found in
the :ref:`log-inspection` section of the tutorial.

.. note::

  This section used ``LogAscii::use_json=T`` in the Zeek invocation, which
  outputs JSON format logs. The remaining invocations in this guide will not
  provide that argument, so Zeek will output tab-separated (TSV) logs. You may
  add ``LogAscii::use_json=T`` to future Zeek invocations if you want JSON
  format logs.

Live Traffic
============

Zeek is often used to monitor live network traffic, not just previously captured
traffic. You can provide Zeek with a network interface to monitor traffic. Any
traffic on that interface will be analyzed in order to create logs. For example,
you may run Zeek on the ``en0`` network device (change ``en0`` to the device you
want to monitor traffic on):

.. code-block:: console

     $ zeek -i en0 -C

Root access is typically required to run commands which monitor a network
device.

In another terminal, create the same two HTTP requests we saw earlier via
``curl``:

.. code-block:: console

     $ curl -X GET http://zeek.org
     $ curl -X WEIRD http://zeek.org

Return to the terminal running Zeek and use Ctrl+C to exit. The logs may have
more than just the two entries found before since Zeek will analyze all traffic
on that network device. Entries should still appear in :file:`conn.log`,
:file:`http.log`, and :file:`weird.log` for these commands.

.. note::

  The ``zeek`` invocation above adds a ``-C`` flag. By default, Zeek discards
  network packets with checksum errors. This flag tells Zeek to ignore
  checksums. Modern operating systems and network devices use checksum
  offloading, which leaves the checksums uninitialized. Since Zeek discards
  packets with checksum errors, checksum offloading necessitates the ``-C``
  flag for local network monitoring via Zeek.

Scripting
=========

You can also use Zeek's own scripting language in order to modify and extend
its behavior:

.. code-block:: zeek

     # example.zeek
     event http_request(c: connection, method: string, original_URI: string,
         unescaped_URI: string, version: string)
         {
         print fmt("HTTP request: %s %s (%s->%s)", method, original_URI, c$id$orig_h,
             c$id$resp_h);
         }

This script defines an event handler that will run whenever Zeek sees an HTTP
request. You can run it through Zeek with the data from the pcap you used
earlier:

.. code-block:: console

     $ zeek example.zeek -r quickstart.pcap
     HTTP request: GET / (192.168.1.8->192.0.78.212)
     HTTP request: WEIRD / (192.168.1.8->192.0.78.212)

Or on live traffic:

.. code-block:: console

     $ zeek example.zeek -i en0 -C

In another terminal, run the two ``curl`` commands from before:

.. code-block:: console

     $ curl -X GET http://zeek.org
     $ curl -X WEIRD http://zeek.org

The terminal running Zeek will print each command as it gets processed.

More information on how to use Zeek’s scripting language can be found in the
:doc:`tutorial/scripting/index` section. Experiment with Zeek scripting at
`try.zeek.org <https://try.zeek.org>`_.

Managing Zeek
=============

Zeek comes packaged with ZeekControl (``zeekctl``) to manage more complex
deployments.

The same network device used in the Zeek command line can be used with
``zeekctl``. This will go in a configuration file. For the following example,
``$PREFIX`` will refer to the installation directory. This is likely
``/usr/local/zeek`` if built from source or ``/opt/zeek`` if installed from a
pre-built package.

First, update the configuration’s network interface in
``$PREFIX/etc/node.cfg``. If the device is ``en0``, that would look like:

.. code-block:: console

     [zeek]
     type=standalone
     host=localhost
     interface=en0

You can further configure the ``local.zeek`` script found in
``$PREFIX/share/zeek/site/local.zeek``. ``zeekctl`` loads this script by 
default. It is not overwritten by Zeek upgrades.

Run ``zeekctl`` in order to start an interactive prompt and manage your Zeek
deployment:

.. code-block:: console

     $ zeekctl
     Hint: Run the zeekctl "deploy" command to get started.

     Welcome to ZeekControl 2.5.0-76

     Type "help" for help.

     [ZeekControl] >

Then run ``deploy`` to get started:

.. code-block:: console

     [ZeekControl] > deploy

In another terminal, run the same two curl commands from before:

.. code-block:: console

     $ curl -X GET http://zeek.org
     $ curl -X WEIRD http://zeek.org

Then return to the ZeekControl prompt and stop it:

.. code-block:: console

     [ZeekControl] > stop
     stopping zeek ...

And exit from ``zeekctl``:

.. code-block:: console

     [ZeekControl] > exit

The logs from ZeekControl will not appear in your current directory. Instead,
they will appear in ``$PREFIX/logs/current`` when running. Since the process was
stopped, they will appear in a directory with the current date within 
``$PREFIX/logs/`` - such as ``$PREFIX/logs/2025-01-01/``.

These logs are compressed as ``.log.gz`` files from gzip_. You may decompress
these via ``gunzip`` then read them, or use gzip’s packaged ``zcat`` command.
On Mac, this looks like:

.. code-block:: console

     $ zcat < $PREFIX/logs/2025-01-08/weird.11:03:38-11:03:43.log.gz
     <...>
     1736352218.157077       CFvENWVlkwVHhLL35       2603:6081:18f0:99e0:7da2:6b81:9a83:cb4e 57823   2606:2800:21f:cb07:6820:80da:af6b:8b2c   80      unknown_HTTP_method     WEIRD   F       zeek    -

The logs contain the ``WEIRD`` HTTP request.

More information on using ZeekControl can be found in the
`ZeekControl documentation`_. More information on setting up a cluster can be
found in the :doc:`cluster-setup` section.

Clusters
========

ZeekControl is also used to manage a cluster of Zeek processes. A cluster
contains many processes which analyze traffic together. For this example, all
nodes will be local, but they may also be split among multiple hosts.

First, return to the ``$PREFIX/etc/node.cfg`` configuration file. It currently
contains one "standalone" node: 

.. code-block:: console

     [zeek]
     type=standalone
     host=localhost
     interface=en0


A standalone node is not in a cluster. Instead, this will change to multiple
nodes which work together. The following configuration is commented out in the
``node.cfg`` file by default. Remove the ``[zeek]`` node from above and paste
this into the file:

.. code-block:: console

     [logger]
     type=logger
     host=localhost

     [manager]
     type=manager
     host=localhost

     [proxy]
     type=proxy
     host=localhost

     [worker]
     type=worker
     host=localhost
     interface=en0

Now start ``zeekctl`` again with the ``zeekctl`` console command and run it
with ``deploy``:

.. code-block:: console

     $ zeekctl
     Hint: Run the zeekctl "deploy" command to get started.

     Welcome to ZeekControl 2.5.0-76

     Type "help" for help.

     [ZeekControl] > deploy

Now check the status of the cluster with the ``top`` command:

.. code-block:: console

     [ZeekControl] > top

     Name         Type    Host             Pid     VSize  Rss  Cpu   Cmd
     logger       logger  localhost        XXXX     83M    83M   0%  zeek
     manager      manager localhost        XXXX     82M    82M   0%  zeek
     proxy        proxy   localhost        XXXX     82M    82M   0%  zeek
     worker       worker  localhost        XXXX     84M    84M   0%  zeek

This is how you can easily check the status of the running cluster. As before,
run the two ``curl`` commands in another terminal:

.. code-block:: console

     $ curl -X GET http://zeek.org
     $ curl -X WEIRD http://zeek.org

Then interrupt the ``top`` command with Ctrl+C and stop the cluster:

.. code-block:: console

     [ZeekControl] > stop
     stopping workers ...
     stopping proxy ...
     stopping manager ...
     stopping logger ...
     [ZeekControl] > exit

As before, the logs will be in the ``$PREFIX/logs/`` directory. Check for the
weird the same way as before:

.. code-block:: console

     $ zcat < $PREFIX/logs/2025-05-14/weird.08:58:26-08:58:31.log.gz
     <...>
     1747227503.828889       C3aXMM2AC3jzZbKl6i      192.168.1.8     60818   192.0.78.150    80 unknown_HTTP_method      WEIRD   F       worker  -

Users can distribute work across multiple processes or machines with clusters.
See the `ZeekControl documentation`_ for more information on managing clusters
and :doc:`cluster-setup` for more information on cluster setup.

Next Steps
==========

By this point, we’ve built up from Zeek's simplest use case to clusters.
Each section has links to guide further discovery. Here are some extra
considerations:

* Follow the interactive Zeek tutorial at
  `try.zeek.org <https://try.zeek.org>`_.
* Read more of the documentation: the documentation can be read sequentially.
  Documentation for Zeek's out-of-the-box logs can be found in the
  :doc:`logs/index` section.
* Browse scripts from :samp:`{$PREFIX}/share/zeek/policy` that may be useful to
  load. Their documentation is found in the 
  :ref:`overview of script packages <script-packages>`.
* Review the FAQ_.
* Join the Zeek community :slacklink:`Slack workspace <>` or
  :discourselink:`forum <>` to interact with fellow Zeekers and Zeek core
  developers.
* Track Zeek code releases on the `Get Zeek`_ page. Find the release notes
  under each release. These release notes reference the :file:`NEWS` file found
  in the `Zeek source code`_. The :file:`CHANGES` file gives a more granular
  view of each change.
