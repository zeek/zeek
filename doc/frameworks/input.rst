
.. _framework-input:

===============
Input Framework
===============

.. rst-class:: opening

   Bro now features a flexible input framework that allows users
   to import data into Bro. Data is either read into Bro tables or
   converted to events which can then be handled by scripts.
   This document gives an overview of how to use the input framework
   with some examples. For more complex scenarios it is
   worthwhile to take a look at the unit tests in
   ``testing/btest/scripts/base/frameworks/input/``.

.. contents::

Reading Data into Tables
========================

Probably the most interesting use-case of the input framework is to
read data into a Bro table.

By default, the input framework reads the data in the same format
as it is written by the logging framework in Bro - a tab-separated
ASCII file.

We will show the ways to read files into Bro with a simple example.
For this example we assume that we want to import data from a blacklist
that contains server IP addresses as well as the timestamp and the reason
for the block.

An example input file could look like this:

::

        #fields ip timestamp reason
        192.168.17.1 1333252748 Malware host
        192.168.27.2 1330235733 Botnet server
        192.168.250.3 1333145108 Virus detected

To read a file into a Bro table, two record types have to be defined.
One contains the types and names of the columns that should constitute the
table keys and the second contains the types and names of the columns that
should constitute the table values.

In our case, we want to be able to lookup IPs. Hence, our key record
only contains the server IP. All other elements should be stored as
the table content.

The two records are defined as:

.. code:: bro

        type Idx: record {
                ip: addr;
        };

        type Val: record {
                timestamp: time;
                reason: string;
        };

Note that the names of the fields in the record definitions have to correspond
to the column names listed in the '#fields' line of the log file, in this
case 'ip', 'timestamp', and 'reason'.

The log file is read into the table with a simple call of the ``add_table``
function:

.. code:: bro

        global blacklist: table[addr] of Val = table();

        Input::add_table([$source="blacklist.file", $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist]);
        Input::remove("blacklist");

With these three lines we first create an empty table that should contain the
blacklist data and then instruct the input framework to open an input stream
named ``blacklist`` to read the data into the table. The third line removes the
input stream again, because we do not need it any more after the data has been
read.

Because some data files can - potentially - be rather big, the input framework
works asynchronously. A new thread is created for each new input stream.
This thread opens the input data file, converts the data into a Bro format and
sends it back to the main Bro thread.

Because of this, the data is not immediately accessible. Depending on the
size of the data source it might take from a few milliseconds up to a few
seconds until all data is present in the table. Please note that this means
that when Bro is running without an input source or on very short captured
files, it might terminate before the data is present in the system (because
Bro already handled all packets before the import thread finished).

Subsequent calls to an input source are queued until the previous action has
been completed. Because of this, it is, for example, possible to call
``add_table`` and ``remove`` in two subsequent lines: the ``remove`` action
will remain queued until the first read has been completed.

Once the input framework finishes reading from a data source, it fires
the ``end_of_data`` event. Once this event has been received all data
from the input file is available in the table.

.. code:: bro

        event Input::end_of_data(name: string, source: string) {
                # now all data is in the table
                print blacklist;
        }

The table can also already be used while the data is still being read - it
just might not contain all lines in the input file when the event has not
yet fired. After it has been populated it can be used like any other Bro
table and blacklist entries can easily be tested:

.. code:: bro

        if ( 192.168.18.12 in blacklist )
                # take action


Re-reading and streaming data
-----------------------------

For many data sources, like for many blacklists, the source data is continually
changing. For these cases, the Bro input framework supports several ways to
deal with changing data files.

The first, very basic method is an explicit refresh of an input stream. When
an input stream is open, the function ``force_update`` can be called. This
will trigger a complete refresh of the table; any changed elements from the
file will be updated.  After the update is finished the ``end_of_data``
event will be raised.

In our example the call would look like:

.. code:: bro

        Input::force_update("blacklist");

The input framework also supports two automatic refresh modes. The first mode
continually checks if a file has been changed. If the file has been changed, it
is re-read and the data in the Bro table is updated to reflect the current
state.  Each time a change has been detected and all the new data has been
read into the table, the ``end_of_data`` event is raised.

The second mode is a streaming mode. This mode assumes that the source data
file is an append-only file to which new data is continually appended. Bro
continually checks for new data at the end of the file and will add the new
data to the table.  If newer lines in the file have the same index as previous
lines, they will overwrite the values in the output table.  Because of the
nature of streaming reads (data is continually added to the table),
the ``end_of_data`` event is never raised when using streaming reads.

The reading mode can be selected by setting the ``mode`` option of the
add_table call.  Valid values are ``MANUAL`` (the default), ``REREAD``
and ``STREAM``.

Hence, when adding ``$mode=Input::REREAD`` to the previous example, the
blacklist table will always reflect the state of the blacklist input file.

.. code:: bro

        Input::add_table([$source="blacklist.file", $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist, $mode=Input::REREAD]);

Receiving change events
-----------------------

When re-reading files, it might be interesting to know exactly which lines in
the source files have changed.

For this reason, the input framework can raise an event each time when a data
item is added to, removed from or changed in a table.

The event definition looks like this:

.. code:: bro

        event entry(description: Input::TableDescription, tpe: Input::Event, left: Idx, right: Val) {
                # act on values
        }

The event has to be specified in ``$ev`` in the ``add_table`` call:

.. code:: bro

        Input::add_table([$source="blacklist.file", $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist, $mode=Input::REREAD, $ev=entry]);

The ``description`` field of the event contains the arguments that were
originally supplied to the add_table call.  Hence, the name of the stream can,
for example, be accessed with ``description$name``. ``tpe`` is an enum
containing the type of the change that occurred.

If a line that was not previously present in the table has been added,
then ``tpe`` will contain ``Input::EVENT_NEW``. In this case ``left`` contains
the index of the added table entry and ``right`` contains the values of the
added entry.

If a table entry that already was present is altered during the re-reading or
streaming read of a file, ``tpe`` will contain ``Input::EVENT_CHANGED``. In
this case ``left`` contains the index of the changed table entry and ``right``
contains the values of the entry before the change. The reason for this is
that the table already has been updated when the event is raised. The current
value in the table can be ascertained by looking up the current table value.
Hence it is possible to compare the new and the old values of the table.

If a table element is removed because it was no longer present during a
re-read, then ``tpe`` will contain ``Input::REMOVED``.  In this case ``left``
contains the index and ``right`` the values of the removed element.


Filtering data during import
----------------------------

The input framework also allows a user to filter the data during the import.
To this end, predicate functions are used. A predicate function is called
before a new element is added/changed/removed from a table. The predicate
can either accept or veto the change by returning true for an accepted
change and false for a rejected change. Furthermore, it can alter the data
before it is written to the table.

The following example filter will reject to add entries to the table when
they were generated over a month ago. It will accept all changes and all
removals of values that are already present in the table.

.. code:: bro

        Input::add_table([$source="blacklist.file", $name="blacklist", $idx=Idx, $val=Val, $destination=blacklist, $mode=Input::REREAD,
                        $pred(typ: Input::Event, left: Idx, right: Val) = {
                                if ( typ != Input::EVENT_NEW ) {
                                        return T;
                                }
                                return ( ( current_time() - right$timestamp ) < (30 day) );
                        }]);

To change elements while they are being imported, the predicate function can
manipulate ``left`` and ``right``. Note that predicate functions are called
before the change is committed to the table. Hence, when a table element is
changed (``tpe`` is ``INPUT::EVENT_CHANGED``), ``left`` and ``right``
contain the new values, but the destination (``blacklist`` in our example)
still contains the old values. This allows predicate functions to examine
the changes between the old and the new version before deciding if they
should be allowed.

Different readers
-----------------

The input framework supports different kinds of readers for different kinds
of source data files. At the moment, the default reader reads ASCII files
formatted in the Bro log file format (tab-separated values). At the moment,
Bro comes with two other readers. The ``RAW`` reader reads a file that is
split by a specified record separator (usually newline). The contents are
returned line-by-line as strings; it can, for example, be used to read
configuration files and the like and is probably
only useful in the event mode and not for reading data to tables.

Another included reader is the ``BENCHMARK`` reader, which is being used
to optimize the speed of the input framework. It can generate arbitrary
amounts of semi-random data in all Bro data types supported by the input
framework.

Currently, Bro supports the following readers in addition to the 
aforementioned ones:

.. toctree::
   :maxdepth: 1

   logging-input-sqlite

Add_table options
-----------------

This section lists all possible options that can be used for the add_table
function and gives a short explanation of their use. Most of the options
already have been discussed in the previous sections.

The possible fields that can be set for a table stream are:

        ``source``
                A mandatory string identifying the source of the data.
                For the ASCII reader this is the filename.

        ``name``
                A mandatory name for the filter that can later be used
                to manipulate it further.

        ``idx``
                Record type that defines the index of the table.

        ``val``
                Record type that defines the values of the table.

        ``reader``
                The reader used for this stream. Default is ``READER_ASCII``.

        ``mode``
                The mode in which the stream is opened. Possible values are
                ``MANUAL``, ``REREAD`` and ``STREAM``.  Default is ``MANUAL``.
                ``MANUAL`` means that the file is not updated after it has
                been read. Changes to the file will not be reflected in the
                data Bro knows.  ``REREAD`` means that the whole file is read
                again each time a change is found. This should be used for
                files that are mapped to a table where individual lines can
                change.  ``STREAM`` means that the data from the file is
                streamed. Events / table entries will be generated as new
                data is appended to the file.

        ``destination``
                The destination table.

        ``ev``
                Optional event that is raised, when values are added to,
                changed in, or deleted from the table.  Events are passed an
                Input::Event description as the first argument, the index
                record as the second argument and the values as the third
                argument.

        ``pred``
                Optional predicate, that can prevent entries from being added
                to the table and events from being sent.

        ``want_record``
                Boolean value, that defines if the event wants to receive the
                fields inside of a single record value, or individually
                (default).  This can be used if ``val`` is a record
                containing only one type. In this case, if ``want_record`` is
                set to false, the table will contain elements of the type
                contained in ``val``.

Reading Data to Events
======================

The second supported mode of the input framework is reading data to Bro
events instead of reading them to a table using event streams.

Event streams work very similarly to table streams that were already
discussed in much detail. To read the blacklist of the previous example
into an event stream, the following Bro code could be used:

.. code:: bro

        type Val: record {
                ip: addr;
                timestamp: time;
                reason: string;
        };

        event blacklistentry(description: Input::EventDescription, tpe: Input::Event, ip: addr, timestamp: time, reason: string) {
                # work with event data
        }

        event bro_init() {
                Input::add_event([$source="blacklist.file", $name="blacklist", $fields=Val, $ev=blacklistentry]);
        }


The main difference in the declaration of the event stream is, that an event
stream needs no separate index and value declarations -- instead, all source
data types are provided in a single record definition.

Apart from this, event streams work exactly the same as table streams and
support most of the options that are also supported for table streams.

The options that can be set when creating an event stream with
``add_event`` are:

        ``source``
                A mandatory string identifying the source of the data.
                For the ASCII reader this is the filename.

        ``name``
                A mandatory name for the stream that can later be used
                to remove it.

        ``fields``
                Name of a record type containing the fields, which should be
                retrieved from the input stream.

        ``ev``
                The event which is fired, after a line has been read from the
                input source.  The first argument that is passed to the event
                is an Input::Event structure, followed by the data, either
                inside of a record (if ``want_record is set``) or as
                individual fields.  The Input::Event structure can contain
                information, if the received line is ``NEW``, has been
                ``CHANGED`` or ``DELETED``. Since the ASCII reader cannot
                track this information for event filters, the value is
                always ``NEW`` at the moment.

        ``mode``
                The mode in which the stream is opened. Possible values are
                ``MANUAL``, ``REREAD`` and ``STREAM``.  Default is ``MANUAL``.
                ``MANUAL`` means that the file is not updated after it has
                been read. Changes to the file will not be reflected in the
                data Bro knows.  ``REREAD`` means that the whole file is read
                again each time a change is found. This should be used for
                files that are mapped to a table where individual lines can
                change.  ``STREAM`` means that the data from the file is
                streamed. Events / table entries will be generated as new
                data is appended to the file.

        ``reader``
                The reader used for this stream. Default is ``READER_ASCII``.

        ``want_record``
                Boolean value, that defines if the event wants to receive the
                fields inside of a single record value, or individually
                (default). If this is set to true, the event will receive a
                single record of the type provided in ``fields``.



