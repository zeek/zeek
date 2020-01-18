
.. _mime-stats:

====================
MIME Type Statistics
====================

Files are constantly transmitted over HTTP on regular networks. These
files belong to a specific category (e.g., executable, text, image) 
identified by a `Multipurpose Internet Mail Extension (MIME)
<http://en.wikipedia.org/wiki/MIME>`_. Although MIME was originally
developed to identify the type of non-text attachments on email, it is
also used by a web browser to identify the type of files transmitted and
present them accordingly.

In this tutorial, we will demonstrate how to use the Sumstats Framework 
to collect statistical information based on MIME types; specifically,
the total number of occurrences, size in bytes, and number of unique
hosts transmitting files over HTTP per each type. For instructions on
extracting and creating a local copy of these files, visit :ref:`this 
tutorial <http-monitor>`.

------------------------------------------------
MIME Statistics with Sumstats
------------------------------------------------

When working with the :ref:`Summary Statistics Framework
<sumstats-framework>`, you need to define three different pieces: (i)
Observations, where the event is observed and fed into the framework.
(ii) Reducers, where observations are collected and measured. (iii)
Sumstats, where the main functionality is implemented.

We start by defining our observation along with a record to store
all statistical values and an observation interval. We are conducting our
observation on the :zeek:see:`HTTP::log_http` event and are interested
in the MIME type, size of the file ("response_body_len"), and the
originator host ("orig_h"). We use the MIME type as our key and create
observers for the other two values.

.. literalinclude:: mimestats.zeek
   :caption:
   :language: zeek
   :linenos:
   :lines: 6-29
   :lineno-start: 6
   :tab-width: 4

.. literalinclude:: mimestats.zeek
   :caption:
   :language: zeek
   :linenos:
   :lines: 54-64
   :lineno-start: 54
   :tab-width: 4

Next, we create the reducers. The first will accumulate file sizes
and the second will make sure we only store a host ID once. Below is
the partial code from a :zeek:see:`zeek_init` handler.

.. literalinclude:: mimestats.zeek
   :caption:
   :language: zeek
   :linenos:
   :lines: 34-37
   :lineno-start: 34
   :tab-width: 4

In our final step, we create the SumStats where we check for the
observation interval.  Once it expires, we populate the record
(defined above) with all the relevant data and write it to a log.

.. literalinclude:: mimestats.zeek
   :caption:
   :language: zeek
   :linenos:
   :lines: 38-51
   :lineno-start: 38
   :tab-width: 4

After putting the three pieces together we end up with the following
final code for our script.

.. literalinclude:: mimestats.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

.. sourcecode:: console

   $ zeek -r http/zeek.org.pcap mimestats.zeek
   #separator \x09
   #set_separator    ,
   #empty_field      (empty)
   #unset_field      -
   #path     mime_metrics
   #open     2018-12-14-16-25-06
   #fields   ts      ts_delta        mtype   uniq_hosts      hits    bytes
   #types    time    interval        string  count   count   count
   1389719059.311698 300.000000      image/png       1       9       82176
   1389719059.311698 300.000000      image/gif       1       1       172
   1389719059.311698 300.000000      image/x-icon    1       2       2300
   1389719059.311698 300.000000      text/html       1       2       42231
   1389719059.311698 300.000000      text/plain      1       15      128001
   1389719059.311698 300.000000      image/jpeg      1       1       186859
   1389719059.311698 300.000000      application/pgp-signature       1       1       836
   #close    2018-12-14-16-25-06

.. note::

    The redefinition of :zeek:see:`Site::local_nets` is only done inside
    this script to make it a self-contained example.  It's typically
    redefined somewhere else.
