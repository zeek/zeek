.. _invoking-zeek:

###############
 Invoking Zeek
###############

Invoking Zeek When invoked standalone, Zeek is primarily used from the
command line. You can read a trace file using the `-r` flag, like from
the setup:

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek -r ../traces/quickstart.pcap

You can also use Zeek to analyze live traffic. You have to interrupt the
command to get Zeek to stop with Ctrl+C:

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek -C -i eth0

You can test this by entering in another Bash prompt and using ``ping
google.com`` or similar. Once you use Ctrl+C to exit, you should see
logs for that connection.

On local environments, it may be useful to tell Zeek to ignore checksums
with the ``-C`` flag. Otherwise, Zeek discards any packets with checksum
errors - due to checksum offloading, this may be all packets!

*************************
 Providing Script Values
*************************

You may also modify Zeek script values directly from the command line.
We saw this in the quickstart when analyzing the quickstart trace:

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek -r ../traces/quickstart.pcap LogAscii::use_json=T

but this can be extended further - you can modify any exported script
``option`` or ``&redef`` globals! For example, you can use this in order
to increase the number of invalid SMTP transactions needed to disable
the analyzer: TODO: switch to HTTP::default_capture_password?
on a provided pcap

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek -i en0 SMTP::max_invalid_mail_transactions=500

You can even use ``zeek -e`` and provide arbitrary quoted Zeek script
segments:

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek -e "print \"hello\"; print\"there\";"
      hello
      there

******
 Misc
******

Zeek also has a built-in optimization engine called ZAM. This has been
stable since Zeek 7.0. To enable it, just add the ``-O ZAM`` flag to the
Zeek invocation, like so:

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek -O ZAM ../traces/quickstart.pcap

This will first compile Zeek’s script into a lower-level form, then
execute that form. For more information, you can read more about it here
(TODO link).

TODO: Talk about environment variables, like ZEEKPATH and
ZEEK_PLUGIN_PATH maybe

This was just an overview of Zeek’s possible options. Feel free to
browse Zeek’s ``--help`` output for more information:

   .. code:: console

      root@zeek-tutorial:/opt/scratch $ zeek --help
      ...
