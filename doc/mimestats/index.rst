
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
observation on the :bro:see:`HTTP::log_http` event and are interested
in the MIME type, size of the file ("response_body_len"), and the
originator host ("orig_h"). We use the MIME type as our key and create
observers for the other two values.

.. btest-include:: ${DOC_ROOT}/mimestats/mimestats.bro
    :lines: 6-29, 54-64

Next, we create the reducers. The first will accumulate file sizes
and the second will make sure we only store a host ID once. Below is
the partial code from a :bro:see:`bro_init` handler.

.. btest-include:: ${DOC_ROOT}/mimestats/mimestats.bro
    :lines: 34-37

In our final step, we create the SumStats where we check for the
observation interval.  Once it expires, we populate the record
(defined above) with all the relevant data and write it to a log.

.. btest-include:: ${DOC_ROOT}/mimestats/mimestats.bro
    :lines: 38-51

After putting the three pieces together we end up with the following final code for
our script.

.. btest-include:: ${DOC_ROOT}/mimestats/mimestats.bro

.. btest:: mimestats

    @TEST-EXEC: btest-rst-cmd bro -r ${TRACES}/http/bro.org.pcap ${DOC_ROOT}/mimestats/mimestats.bro
    @TEST-EXEC: btest-rst-include mime_metrics.log

.. note::

    The redefinition of :bro:see:`Site::local_nets` is only done inside
    this script to make it a self-contained example.  It's typically
    redefined somewhere else.
