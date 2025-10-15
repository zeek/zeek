
.. _sumstats-framework:

==================
Summary Statistics
==================

.. TODO: integrate BoZ revisions

.. rst-class:: opening

    Measuring aspects of network traffic is an extremely common task in Zeek.
    Zeek provides data structures which make this very easy as well in
    simplistic cases such as size limited trace file processing. In
    real-world deployments though, there are difficulties that arise from
    clusterization (many processes sniffing traffic) and unbounded data sets
    (traffic never stops). The Summary Statistics (otherwise referred to as
    SumStats) framework aims to define a mechanism for consuming unbounded
    data sets and making them measurable in practice on large clustered and
    non-clustered Zeek deployments.

Overview
========

The Sumstat processing flow is broken into three pieces. Observations, where
some aspect of an event is observed and fed into the Sumstats framework.
Reducers, where observations are collected and measured, typically by taking
some sort of summary statistic measurement like average or variance (among
others). Sumstats, where reducers have an epoch (time interval) that their
measurements are performed over along with callbacks for monitoring thresholds
or viewing the collected and measured data.

Terminology
===========

    Observation

        A single point of data. Observations have a few components of their
        own. They are part of an arbitrarily named observation stream, they
        have a key that is something the observation is about, and the actual
        observation itself.

    Reducer

        Calculations are applied to an observation stream here to reduce the
        full unbounded set of observations down to a smaller representation.
        Results are collected within each reducer per-key so care must be
        taken to keep the total number of keys tracked down to a reasonable
        level.

    Sumstat

        The final definition of a Sumstat where one or more reducers is
        collected over an interval, also known as an epoch. Thresholding can
        be applied here along with a callback in the event that a threshold is
        crossed. Additionally, a callback can be provided to access each
        result (per-key) at the end of each epoch.

Examples
========

These examples may seem very simple to an experienced Zeek script developer and
they're intended to look that way. Keep in mind that these scripts will work
on small single process Zeek instances as well as large many-worker clusters.
The complications from dealing with flow based load balancing can be ignored
by developers writing scripts that use Sumstats due to its built-in cluster
transparency.

Printing the number of connections
----------------------------------

Sumstats provides a simple way of approaching the problem of trying to count
the number of connections over a given time interval.  Here is a script with
inline documentation that does this with the Sumstats framework:

.. literalinclude:: sumstats-countconns.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

When run on a sample PCAP file from the Zeek test suite, the following output
is created:

.. code-block:: console

   $ zeek -r workshop_2011_browse.trace sumstats-countconns.zeek
   Number of connections established: 6

Toy scan detection
------------------

Taking the previous example even further, we can implement a simple detection
to demonstrate the thresholding functionality.  This example is a toy to
demonstrate how thresholding works in Sumstats and is not meant to be a
real-world functional example.

.. literalinclude:: sumstats-toy-scan.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Let's see if there are any hosts that crossed the threshold in a PCAP file
containing a host running nmap:

.. code-block:: console

   $ zeek -r nmap-vsn.trace sumstats-toy-scan.zeek
   192.168.1.71 attempted 5 or more connections

It seems the host running nmap was detected!
