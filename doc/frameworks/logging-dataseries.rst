
=============================
Binary Output with DataSeries
=============================

.. rst-class:: opening

   Bro's default ASCII log format is not exactly the most efficient
   way for storing and searching large volumes of data. An an
   alternative, Bro comes with experimental support for `DataSeries
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
to use recent development versions for both packages, which you can
download from github like this::

    git clone http://github.com/dataseries/Lintel
    git clone http://github.com/dataseries/DataSeries

To build and install the two into ``<prefix>``, do::

    ( cd Lintel     && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=<prefix> .. && make && make install )
    ( cd DataSeries && mkdir build && cd build && cmake -DCMAKE_INSTALL_PREFIX=<prefix> .. && make && make install )

Please refer to the packages' documentation for more information about
the installation process. In particular, there's more information on
required and optional `dependencies for Lintel
<https://raw.github.com/dataseries/Lintel/master/doc/dependencies.txt>`_
and `dependencies for DataSeries
<https://raw.github.com/dataseries/DataSeries/master/doc/dependencies.txt>`_.
For users on RedHat-style systems, you'll need the following::

    yum install libxml2-devel boost-devel

Compiling Bro with DataSeries Support
-------------------------------------

Once you have installed DataSeries, Bro's ``configure`` should pick it
up automatically as long as it finds it in a standard system location.
Alternatively, you can specify the DataSeries installation prefix
manually with ``--with-dataseries=<prefix>``. Keep an eye on
``configure``'s summary output, if it looks like the following, Bro
found DataSeries and will compile in the support::

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
Log::default_writer=Log::WRITER_DATASERIES;`` to your ``local.bro``.
For testing, you can also just pass that on the command line::

    bro -r trace.pcap Log::default_writer=Log::WRITER_DATASERIES

With that, Bro will now write all its output into DataSeries files
``*.ds``. You can inspect these using DataSeries's set of command line
tools, which its installation process installs into ``<prefix>/bin``.
For example, to convert a file back into an ASCII representation::

    $ ds2txt conn.log
    [... We skip a bunch of metadata here ...]
    ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state local_orig missed_bytes history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes
    1300475167.096535 CRCC5OdDlXe 141.142.220.202 5353 224.0.0.251 5353 udp dns 0.000000 0 0 S0 F 0 D 1 73 0 0
    1300475167.097012 o7XBsfvo3U1 fe80::217:f2ff:fed7:cf65 5353 ff02::fb 5353 udp  0.000000 0 0 S0 F 0 D 1 199 0 0
    1300475167.099816 pXPi1kPMgxb 141.142.220.50 5353 224.0.0.251 5353 udp  0.000000 0 0 S0 F 0 D 1 179 0 0
    1300475168.853899 R7sOc16woCj 141.142.220.118 43927 141.142.2.2 53 udp dns 0.000435 38 89 SF F 0 Dd 1 66 1 117
    1300475168.854378 Z6dfHVmt0X7 141.142.220.118 37676 141.142.2.2 53 udp dns 0.000420 52 99 SF F 0 Dd 1 80 1 127
    1300475168.854837 k6T92WxgNAh 141.142.220.118 40526 141.142.2.2 53 udp dns 0.000392 38 183 SF F 0 Dd 1 66 1 211
    [...]

(``--skip-all`` suppresses the metadata.)

Note that the ASCII conversion is *not* equivalent to Bro's default
output format.

You can also switch only individual files over to DataSeries by adding
code like this to your ``local.bro``:

.. code:: bro

    event bro_init()
        {
        local f = Log::get_filter(Conn::LOG, "default"); # Get default filter for connection log.
        f$writer = Log::WRITER_DATASERIES;               # Change writer type.
        Log::add_filter(Conn::LOG, f);                   # Replace filter with adapted version.
        }

Bro's DataSeries writer comes with a few tuning options, see
:doc:`/scripts/base/frameworks/logging/writers/dataseries.bro`.

Working with DataSeries
=======================

Here are a few examples of using DataSeries command line tools to work
with the output files.

* Printing CSV::

    $ ds2txt --csv conn.log
    ts,uid,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,service,duration,orig_bytes,resp_bytes,conn_state,local_orig,missed_bytes,history,orig_pkts,orig_ip_bytes,resp_pkts,resp_ip_bytes
    1258790493.773208,ZTtgbHvf4s3,192.168.1.104,137,192.168.1.255,137,udp,dns,3.748891,350,0,S0,F,0,D,7,546,0,0
    1258790451.402091,pOY6Rw7lhUd,192.168.1.106,138,192.168.1.255,138,udp,,0.000000,0,0,S0,F,0,D,1,229,0,0
    1258790493.787448,pn5IiEslca9,192.168.1.104,138,192.168.1.255,138,udp,,2.243339,348,0,S0,F,0,D,2,404,0,0
    1258790615.268111,D9slyIu3hFj,192.168.1.106,137,192.168.1.255,137,udp,dns,3.764626,350,0,S0,F,0,D,7,546,0,0
    [...]

  Add ``--separator=X`` to set a different separator.

* Extracting a subset of columns::

    $ ds2txt --select '*' ts,id.resp_h,id.resp_p --skip-all conn.log
    1258790493.773208 192.168.1.255 137
    1258790451.402091 192.168.1.255 138
    1258790493.787448 192.168.1.255 138
    1258790615.268111 192.168.1.255 137
    1258790615.289842 192.168.1.255 138
    [...]

* Filtering rows::

    $ ds2txt --where '*' 'duration > 5 && id.resp_p > 1024' --skip-all  conn.ds
    1258790631.532888 V8mV5WLITu5 192.168.1.105 55890 239.255.255.250 1900 udp  15.004568 798 0 S0 F 0 D 6 966 0 0
    1258792413.439596 tMcWVWQptvd 192.168.1.105 55890 239.255.255.250 1900 udp  15.004581 798 0 S0 F 0 D 6 966 0 0
    1258794195.346127 cQwQMRdBrKa 192.168.1.105 55890 239.255.255.250 1900 udp  15.005071 798 0 S0 F 0 D 6 966 0 0
    1258795977.253200 i8TEjhWd2W8 192.168.1.105 55890 239.255.255.250 1900 udp  15.004824 798 0 S0 F 0 D 6 966 0 0
    1258797759.160217 MsLsBA8Ia49 192.168.1.105 55890 239.255.255.250 1900 udp  15.005078 798 0 S0 F 0 D 6 966 0 0
    1258799541.068452 TsOxRWJRGwf 192.168.1.105 55890 239.255.255.250 1900 udp  15.004082 798 0 S0 F 0 D 6 966 0 0
    [...]

* Calculate some statistics:

    Mean/stddev/min/max over a column::

        $ dsstatgroupby '*' basic duration from conn.ds
        # Begin DSStatGroupByModule
        # processed 2159 rows, where clause eliminated 0 rows
        # count(*), mean(duration), stddev, min, max
        2159, 42.7938, 1858.34, 0, 86370
        [...]

    Quantiles of total connection volume::

        $ dsstatgroupby '*' quantile 'orig_bytes + resp_bytes' from conn.ds
        [...]
        2159 data points, mean 24616 +- 343295 [0,1.26615e+07]
        quantiles about every 216 data points:
        10%: 0, 124, 317, 348, 350, 350, 601, 798, 1469
        tails: 90%: 1469, 95%: 7302, 99%: 242629, 99.5%: 1226262
        [...]

The ``man`` pages for these tools show further options, and their
``-h`` option gives some more information (either can be a bit cryptic
unfortunately though).

Deficiencies
------------

Due to limitations of the DataSeries format, one cannot inspect its
files before they have been fully written. In other words, when using
DataSeries, it's currently not possible to inspect the live log
files inside the spool directory before they are rotated to their
final location. It seems that this could be fixed with some effort,
and we will work with DataSeries development team on that if the
format gains traction among Bro users.

Likewise, we're considering writing custom command line tools for
interacting with DataSeries files, making that a bit more convenient
than what the standard utilities provide.
