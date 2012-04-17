
=============================
Binary Output with DataSeries
=============================

.. rst-class:: opening

   Bro's default ASCII log format is not exactly the most efficient
   way for storing large volumes of data. An an alternative, Bro comes
   with experimental support for `DataSeries
   <http://www.hpl.hp.com/techreports/2009/HPL-2009-323.html>`_
   output, an efficient binary format for recording structured bulk
   data. DataSeries is developed and maintained at HP Labs.

.. contents::

Installing DataSeries
---------------------

To use DataSeries, its libraries must be available at compile-time,
along with the supporting *Lintel* package. Generally, both are
distributed on `HP Labs' web site
<http://tesla.hpl.hp.com/opensource/>`_. Currently, however, you need
to use recent developments of both packages with Bro, which you can
download from github like this::

    git clone http://github.com/eric-anderson/Lintel
    git clone http://github.com/eric-anderson/DataSeries

To then build and install the two into ``<prefix>``, do::

    ( cd Lintel     && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=<prefix> .. && make && make install )
    ( cd DataSeries && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=<prefix> .. && make && make install )

Please refer to the packages' documentation for more information about
the installation process. In particular, there's more information on
required and optional `dependencies for Lintel
<https://raw.github.com/eric-anderson/Lintel/master/doc/dependencies.txt>`_
and `dependencies for DataSeries
<https://raw.github.com/eric-anderson/DataSeries/master/doc/dependencies.txt>`_

Compiling Bro with DataSeries Support
-------------------------------------

Once you have installed DataSeries, Bro's ``configure`` should pick it
up automatically as long as it finds it in a standard system location.
Alternatively, you can specify the DataSeries installation prefix
manually with ``--with-dataseries=<prefix>``. Keep an eye on
``configure``'s summary output, if it looks like this, Bro will indeed
compile in the DataSeries support::

    # ./configure --with-dataseries=/usr/local
    [...]
    ====================|  Bro Build Summary  |=====================
    [...]
    DataSeries:        true
    [...]
    ================================================================

Activating DataSeries
---------------------

The direct way to use DataSeries is to switch *all* log files over to
the binary format. To do that, just add ``redef
Log::default_writer=Log::WRITER_DATASERIES;`` to your ``local.bro`.
For testing, you can also just pass that on the command line::

    bro -r trace.pcap Log::default_writer=Log::WRITER_DATASERIES

With that, Bro will now write all its output into DataSeries files
``*.ds``. You can inspect these using DataSeries's set of command line
tools, which its installation process will have installed into
``<prefix>/bin``. For example, to convert a file back into an ASCII
representation::
    # ds2txt conn .log
    [... We skip a bunch of meta data here ...]
    ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state local_orig missed_bytes history orig_pkts orig_ip_bytes resp_pkts res
    1.3e+09 9CqElRsB9Q 141.142.220.202 5353 224.0.0.251 5353 udp dns 0 0 0 S0 F 0 D 1 73 0 0
    1.3e+09 3bNPfUWuIhb fe80::217:f2ff:fed7:cf65 5353 ff02::fb 5353 udp  0 0 0 S0 F 0 D 1 199 0 0
    1.3e+09 ZoDDN7YuYx3 141.142.220.50 5353 224.0.0.251 5353 udp  0 0 0 S0 F 0 D 1 179 0 0
    [...]

Note that is ASCII format is *not* equivalent to Bro's default format
as DataSeries uses a different internal representation.

You can also switch only individual files over to DataSeries by adding
code like this to your ``local.bro``::

    TODO

Bro's DataSeries writer comes with a few tuning options, see
:doc:`scripts/base/frameworks/logging/writers/dataseries`.

Working with DataSeries
=======================

Here are few examples of using DataSeries command line tools to work
with the output files.

TODO.

TODO
====

* I'm seeing lots of warning on stderr::

    Warning, while packing field ts of record 1, error was > 10%:
        (1334620000 / 1000000 = 1334.62, round() = 1335)
    Warning, while packing field not_valid_after of record 11, error was > 10%:
        (1346460000 / 1000000 = 1346.46, round() = 1346)

* The compiler warn about a depracated method and I'm not immediately
  seeing how to avoid using that.

* For testing our script-level options:

    - Can we get the extentsize from a ``.ds`` file?
    - Can we get the compressio level from a ``.ds`` file?

* ds2txt can apparently not read a file that is currently being
  written. That's not good for the spool directory::

    # ds2txt http.ds
    **** Assertion failure in file
    /DataSeriesSink.cpp, line 301
    **** Failed expression: tail[i] == 0xFF
    **** Details: bad header for the tail of http.ds!

  Can that be worked around?

