.. _invoking-zeek:

###############
 Invoking Zeek
###############

When invoked from the command line, Zeek is primarily used for offline traffic analysis.
You can read a trace file using the ``-r`` flag, like you did during the
setup, to produce logs in the local directory:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap

By default, Zeek does not clean up pre-existing log files and will overwrite any
that it decides to write to. To get a clean slate for the next steps, let's
remove any logs produced by the above command:

.. code:: console

   # rm -f *.log

You can also use Zeek to analyze live traffic. When reading from a network
interface, Zeek runs indefinitely:

.. code:: console

   # zeek -C -i eth0
   listening on eth0

In another command prompt on your system, connect to the container
and use a ping command to create test traffic:

.. code:: console

   $ docker exec -it zeek-tutorial /bin/bash

   # ping example.com -c 1
   PING example.com (23.220.75.232) 56(84) bytes of data.
   64 bytes from a23-220-75-232.deploy.static.akamaitechnologies.com (23.220.75.232): icmp_seq=1 ttl=63 time=90.0 ms

   --- example.com ping statistics ---
   1 packets transmitted, 1 received, 0% packet loss, time 0ms
   rtt min/avg/max/mdev = 89.961/89.961/89.961/0.000 ms
   # exit

Back in the original container, use Ctrl+C to exit Zeek, then run ``ls`` to
see a few log files. Feel free to explore ``conn.log`` and look for
evidence of the above ping! We'll dive deeper into these logs later.

On local environments and with capture files, it's often useful to tell
Zeek to ignore checksums with the ``-C`` flag. Otherwise, Zeek discards
any packets with checksum errors---due to checksum offloading, this may
be all packets in a particular direction!

.. _providing_script_values:
 
*************************
 Providing Script Values
*************************

When Zeek starts up, it first loads a large set of Zeek scripts into
its built-in interpreter. These scripts define what Zeek does with the
traffic it observes. They include many tunable settings. It can be handy
to modify these values directly from the command line. We saw this in
the quickstart when analyzing the quickstart trace, to cause Zeek to log
in JSON instead of TSV:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap LogAscii::use_json=T

This can be extended further---you can modify any exported script
``option``, or ``&redef`` globals! (Don't worry for now about what
exactly these terms mean---in essence, you're adjusting some of Zeek's
many tuning knobs.) For example, you can change the FTP
analyzer to capture passwords and log the necessary FTP command:

.. code:: console

   # zeek -Cr traces/zeek-testing/ftp/ftp-password-pass-command.pcap FTP::default_capture_password=T 'FTP::logged_commands+={"PASS"}'
   # cat ftp.log
   ...

You can even use ``zeek -e`` and provide arbitrary quoted Zeek script
segments:

.. code:: console

   # zeek -e "print \"hello\"; print\"there\";"
   hello
   there

As you begin to make more complex adjustments, it quickly becomes
easier to write your own Zeek scripts. More on this shortly!

**************
 Finding More
**************

This was just an overview of Zeek's possible options. Feel free to
browse Zeek's ``--help`` output for more information:

.. code:: console

   # zeek --help
   zeek version 8.0.4
   ...

There are other options for power-users which have their own
documentation which you can find in the :doc:`grab bag
</advanced/grab-bag/scripting/index>` section.
