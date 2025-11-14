.. _invoking-zeek:

###############
 Invoking Zeek
###############

When invoked standalone, Zeek is primarily used from the command line.
You can read a trace file using the `-r` flag, like you did during the
setup:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -r traces/zeek-doc/quickstart.pcap

You can also use Zeek to analyze live traffic.When reading from an
interface, you can exit Zeek by pressing Ctrl+C.

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -C -i eth0
   listening on eth0

In another command prompt, connect to the container and use a ping
command to test:

.. code:: console

   $ docker exec -it zeek-tutorial /bin/bash

   root@zeek-tutorial:/ $ ping example.com -c 1
   PING example.com (23.220.75.232) 56(84) bytes of data.
   64 bytes from a23-220-75-232.deploy.static.akamaitechnologies.com (23.220.75.232): icmp_seq=1 ttl=63 time=90.0 ms

   --- example.com ping statistics ---
   1 packets transmitted, 1 received, 0% packet loss, time 0ms
   rtt min/avg/max/mdev = 89.961/89.961/89.961/0.000 ms
   root@zeek-tutorial:/ $ exit

Back in the original container, use Ctrl+C to exit, then run ``ls`` to
see a few log files. We'll dive deeper into these logs later.

On local environments and with capture files, it may be useful to tell
Zeek to ignore checksums with the ``-C`` flag. Otherwise, Zeek discards
any packets with checksum errors - due to checksum offloading, this may
be all packets in a particular direction!

*************************
 Providing Script Values
*************************

You may also modify Zeek script values directly from the command line.
We saw this in the quickstart when analyzing the quickstart trace, to
cause Zeek to log in JSON instead of TSV:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -r traces/zeek-doc/quickstart.pcap LogAscii::use_json=T

Or in the setup, when we changed the default logging directory:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -r traces/zeek-doc/quickstart.pcap Log::default_logdir=scratch

But this can be extended further - you can modify any exported script
``option`` or ``&redef`` globals! For example, you can change the FTP
analyzer to capture passwords and log the necessary command:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -Cr traces/zeek-testing/ftp/ftp-password-pass-command.pcap "FTP::default_capture_password=T; FTP::logged_commands+={\"PASS\"};"
   root@zeek-tutorial:/opt/zeek-training $ cat ftp.log
   ...

You can even use ``zeek -e`` and provide arbitrary quoted Zeek script
segments:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek -e "print \"hello\"; print\"there\";"
   hello
   there

**************
 Finding More
**************

This was just an overview of Zeek’s possible options. Feel free to
browse Zeek’s ``--help`` output for more information:

.. code:: console

   root@zeek-tutorial:/opt/zeek-training $ zeek --help
   zeek version 8.0.3
   ...

There are other options for power-users which have their own
documentation which you can find in the :doc:`grab bag
</grab-bag/scripting/index>` section.
