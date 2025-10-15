
.. _framework-input:

===============
Input Framework
===============

Zeek features a flexible input framework that allows users to import arbitrary
data into Zeek. Data is either read into Zeek tables or directly converted to
events for scripts to handle as they see fit. A modular reader architecture
allows reading from files, databases, or other data sources.

This chapter gives an overview of how to use the input framework, with
examples. For more complex scenarios take a look at the test cases in
:file:`testing/btest/scripts/base/frameworks/input/` in the Zeek distribution.

.. note::

  The input framework has no awareness of Zeek’s cluster architecture. Zeek
  supports all of the mechanisms covered below on any cluster node. The config
  and intelligence frameworks both leverage the input framework, adding logic
  that applies the input framework on the manager node, distributing ingested
  information across the cluster via events.

Reading Data into Tables
========================

Probably the most interesting use-case of the input framework is to read data
into a Zeek table. By default, the input framework reads the data in the same
format as it is written by Zeek’s logging framework: a tab-separated ASCII
file.

We will show the ways to read files into Zeek with a simple example. For this
example we assume that we want to import data from a denylist that contains
server IP addresses as well as the timestamp and the reason for the block.

An example input file could look like this (note that all fields must be
tab-separated)::

  #fields ip timestamp reason
  192.168.17.1 1333252748 Malware host
  192.168.27.2 1330235733 Botnet server
  192.168.250.3 1333145108 Virus detected

To read a file into a Zeek table, two record types have to be defined. One
contains the types and names of the columns that should constitute the table
keys, and the second contains the types and names of the columns that should
constitute the table values.

In our case, we want to be able to look up IPs. Hence, our key record only
contains the server IP. All other elements should be stored as the table
content.

.. code-block:: zeek

  type Idx: record {
      ip: addr;
  };

  type Val: record {
      timestamp: time;
      reason: string;
  };

Note that the names of the fields in the record definitions must correspond to
the column names listed in the ``#fields`` line of the input file, in this case
``ip``, ``timestamp``, and ``reason``. Also note that the ordering of the
columns does not matter, because each column is identified by name.

The input file is read into the table with a call of the
:zeek:see:`Input::add_table` function:

.. code-block:: zeek

  global denylist: table[addr] of Val = table();

  event zeek_init() {
      Input::add_table([$source="denylist.file", $name="denylist",
                        $idx=Idx, $val=Val, $destination=denylist]);
      Input::remove("denylist");
  }

With these three lines we first create an empty table that should receive the
denylist data and then instruct the input framework to open an input stream
named “denylist” to read the data into the table. The third line removes the
input stream again, because we do not need it any more after the data has been
read.

Note that while the key and content records may use :zeek:attr:`&optional`
fields, omitting columns (usually via the "-" character) requires care. Since
the key record's columns expand into a list of values for indexing into the
receiving table (note how in the above example ``denylist`` is indexed via a
plain ``addr``) and all of those values must be present for indexing, you cannot
in practice omit these values. For content records, omitting is meaningful, but
only permitted for columns with the :zeek:attr:`&optional` attribute. The
framework skips offending input lines with a warning.

.. note::

  Prior to version 4.1 Zeek accepted such inputs, unsafely. When transitioning
  from such versions to Zeek 4.1 or newer, users with omitted fields in their
  input data may observe discrepancies in the loaded data sets.

Asynchronous processing
-----------------------

Since some data files might be rather large, the input framework works
asynchronously. A new thread is created for each new input stream. This thread
opens the input data file, converts the data into an internal format and sends
it back to the main Zeek thread. Because of this, the data is not immediately
accessible. Depending on the size of the data source it might take from a few
milliseconds up to a few seconds until all data is present in the table. Please
note that this means that when Zeek is running without an input source or on
very short captured files, it might terminate before the data is present in the
table (because Zeek already handled all packets before the import thread
finished).

Subsequent calls to an input source are queued until the previous action has
been completed. Because of this it is, for example, possible to call
:zeek:see:`Input::add_table` and :zeek:see:`Input::remove` in two subsequent
lines: the remove action will remain queued until the first read has been
completed.

Once the input framework finishes reading from a data source, it fires the
:zeek:see:`Input::end_of_data` event. Once this event has been received all
data from the input file is available in the table.

.. code-block:: zeek

  event Input::end_of_data(name: string, source: string) {
      # now all data is in the table
      print denylist;
  }

The table can be used while the data is still being read — it just might not
contain all lines from the input file before the event has fired. After the
table has been populated it can be used like any other Zeek table and denylist
entries can easily be tested:

.. code-block:: zeek

  if ( 192.168.18.12 in denylist )
      # take action


Sets instead of tables
----------------------

For some use cases the key/value notion that drives tabular data does not
apply, for example when the main purpose of the data is to test for membership
in a set. The input framework supports this approach by using sets as the
destination data type, and omitting ``$val`` in :zeek:see:`Input::add_table`:

.. code-block:: zeek

  type Idx: record {
      ip: addr;
  };

  global denylist: set[addr] = set();

  event zeek_init() {
      Input::add_table([$source="denylist.file", $name="denylist",
                       $idx=Idx, $destination=denylist]);
      Input::remove("denylist");
  }

Re-reading and streaming data
-----------------------------

For some data sources (such as many denylists), the input data changes
continually. The input framework supports additional techniques to manage such
ever-changing input.

The first, very basic method is an explicit refresh of an input stream. When an
input stream is open (meaning it has not yet been removed by a call to
:zeek:see:`Input::remove`), the function :zeek:see:`Input::force_update` can be
called. This will trigger a complete refresh of the table: any changed elements
from the file will be updated, new ones added, and any elements no longer in
the input data get removed. After the update is finished the
:zeek:see:`Input::end_of_data` event will be raised.

In our example the call would look as follows:

.. code-block:: zeek

  Input::force_update("denylist");

Alternatively, the input framework can automatically refresh the table contents
when it detects a change to the input file. To use this feature you need to
specify a non-default read mode by setting the mode option of the
:zeek:see:`Input::add_table` call. Valid values are :zeek:see:`Input::MANUAL`
(the default), :zeek:see:`Input::REREAD`, and :zeek:see:`Input::STREAM`. For
example, setting the value of the mode option in the previous example would
look like this:

.. code-block:: zeek

  Input::add_table([$source="denylist.file", $name="denylist",
                    $idx=Idx, $val=Val, $destination=denylist,
                    $mode=Input::REREAD]);

When using the reread mode (i.e., ``$mode=Input::REREAD``), Zeek continually
checks if the input file has been changed. If the file has been changed, it is
re-read and the data in the Zeek table is updated to reflect the current state.
Each time a change has been detected and all the new data has been read into
the table, the :zeek:see:`Input::end_of_data` event is raised.

When using the streaming mode (i.e., ``$mode=Input::STREAM``), Zeek
assumes that the input is an append-only file to which new data is
continually appended. Zeek also checks to see if the file being
followed has been renamed or rotated. The file is closed and reopened
when tail detects that the filename being read from has a new inode
number. Zeek continually checks for new data at the end of the file
and will add the new data to the table. If newer lines in the file
have the same table index as previous lines, they will overwrite
the values in the output table. Because of the nature of streaming
reads (data is continually added to the table), the
:zeek:see:`Input::end_of_data` event is never raised when using
streaming reads.

.. tip::

  Change detection happens via periodic “heartbeat” events, defaulting to a
  frequency of once per second as defined by the global
  :zeek:see:`Threading::heartbeat_interval` constant. The reader considers the
  input file changed when the file’s inode or modification time has changed
  since the last check.

Receiving change events
-----------------------

When re-reading files, it might be interesting to know exactly which lines in
the source files have changed. For this reason, the input framework can raise
an event each time when a data item is added to, removed from, or changed in a
table.

The event definition looks like this (note that you can change the name of this
event in your own Zeek script):

.. code-block:: zeek

  event entry(description: Input::TableDescription, tpe: Input::Event,
              left: Idx, right: Val) {
      # do something here...
      print fmt("%s = %s", left, right);
  }

The event must be specified in ``$ev`` in the :zeek:see:`Input::add_table`
call:

.. code-block:: zeek

  Input::add_table([$source="denylist.file", $name="denylist",
                    $idx=Idx, $val=Val, $destination=denylist,
                    $mode=Input::REREAD, $ev=entry]);

The description argument of the event contains the arguments that were
originally supplied to the :zeek:see:`Input::add_table` call. Hence, the name
of the stream can, for example, be accessed with ``description$name``. The
``tpe`` argument of the event is an enum containing the type of the change that
occurred.

If a line that was not previously present in the table has been added, then the
value of ``tpe`` will be :zeek:see:`Input::EVENT_NEW`. In this case left
contains the index of the added table entry and right contains the values of
the added entry.

If a table entry that already was present is altered during the re-reading or
streaming read of a file, then the value of ``tpe`` will be
:zeek:see:`Input::EVENT_CHANGED`.  In this case ``left`` contains the index of
the changed table entry and ``right`` contains the values of the entry before
the change. The reason for this is that the table already has been updated when
the event is raised. The current value in the table can be ascertained by
looking up the current table value. Hence it is possible to compare the new and
the old values of the table.

If a table element is removed because it was no longer present during a
re-read, then the value of ``tpe`` will be :zeek:see:`Input::EVENT_REMOVED`. In
this case ``left`` contains the index and ``right`` the values of the removed
element.

Filtering data during import
----------------------------

The input framework also allows a user to filter the data during the import. To
this end, predicate functions are used. A predicate function is called before a
new element is added/changed/removed from a table. The predicate can either
accept or veto the change by returning true for an accepted change and false
for a rejected change. Furthermore, it can alter the data before it is written
to the table.

The following example filter will reject adding entries to the table when they
were generated over a month ago. It will accept all changes and all removals of
values that are already present in the table.

.. code-block:: zeek

  Input::add_table([$source="denylist.file", $name="denylist",
                    $idx=Idx, $val=Val, $destination=denylist,
                    $mode=Input::REREAD,
                    $pred(tpe: Input::Event, left: Idx, right: Val) = {
                      if ( tpe != Input::EVENT_NEW ) {
                          return T;
                      }
                      return (current_time() - right$timestamp) < 30day;
                    }]);

To change elements while they are being imported, the predicate function can
manipulate ``left`` and ``right``. Note that predicate functions are called
before the change is committed to the table. Hence, when a table element is
changed (``tpe`` is :zeek:see:`Input::EVENT_CHANGED`), ``left`` and ``right``
contain the new values, but the destination (``denylist`` in our example) still
contains the old values. This allows predicate functions to examine the changes
between the old and the new version before deciding if they should be allowed.

Broken input data
-----------------

The input framework notifies you of problems during data ingestion in two ways.
First, reporter messages, ending up in reporter.log, indicate the type of
problem and the file in which the problem occurred::

  #fields ts      level   message location
  0.000000        Reporter::WARNING       denylist.file/Input::READER_ASCII: Did not find requested field ip in input data file denylist.file.   (empty)

Second, the :zeek:see:`Input::TableDescription` and
:zeek:see:`Input::EventDescription` records feature an ``$error_ev`` member to
trigger events indicating the same message and severity levels as shown above.
The use of these events mirrors that of change events.

For both approaches, the framework suppresses repeated messages regarding the
same file, so mistakes in large data files do not trigger a message flood.

Finally, the ASCII reader allows coarse control over the robustness in case of
problems during data ingestion. Concretely, the
:zeek:see:`InputAscii::fail_on_invalid_lines` and
:zeek:see:`InputAscii::fail_on_file_problem` flags indicate whether problems
should merely trigger warnings or lead to processing failure. Both default to
warnings.

Reading Data to Events
======================

The second data ingestion mode of the input framework directly generates Zeek
events from ingested data instead of inserting them to a table. Event streams
work very similarly to the table streams discussed above, and most of the
features discussed (such as predicates for filtering) also work for event
streams. To read the denylist of the previous example into an event stream, we
use the :zeek:see:`Input::add_event` function:

.. code-block:: zeek

  type Val: record {
      ip: addr;
      timestamp: time;
      reason: string;
  };

  event denylistentry(description: Input::EventDescription,
                       tpe: Input::Event, data: Val) {
      # do something here...
      print "data:", data;
  }

  event zeek_init() {
      Input::add_event([$source="denylist.file", $name="denylist",
                       $fields=Val, $ev=denylistentry]);
  }

Event streams differ from table streams in two ways:

* An event stream needs no separate index and value declarations — instead, all
  source data types are provided in a single record definition.
* Since the framework perceives a continuous stream of events, it has no
  concept of a data baseline (e.g. a table) to compare the incoming data to.
  Therefore the change event type (an :zeek:see:`Input::Event` instance,
  ``tpe`` in the above) is currently always :zeek:see:`Input::EVENT_NEW`.

These aside, event streams work exactly the same as table streams and support
most of the options that are also supported for table streams.

Data Readers
============

The input framework supports different kinds of readers for different kinds of
source data files. At the moment, the framework defaults to ingesting ASCII
files formatted in the Zeek log file format (tab-separated values with a
``#fields`` header line). Several other readers are included in Zeek, and Zeek
packages/plugins can provide additional ones.

Reader selection proceeds as follows. The :zeek:see:`Input::default_reader`
variable defines the default reader: :zeek:see:`Input::READER_ASCII`. When you
call :zeek:see:`Input::add_table` or :zeek:see:`Input::add_event` this reader
gets used automatically.  You can override the default by assigning the
``$reader`` member in the description record passed into these calls. See test
cases in :file:`testing/btest/scripts/base/frameworks/input/` for examples.

The ASCII Reader
----------------

The ASCII reader, enabled by default or by selecting
:zeek:see:`Input::READER_ASCII`, understands Zeek’s TSV log format. It actually
understands the full set of directives in the preamble of those log files, e.g.
to define the column separator. This is rarely used, and most commonly input
files merely start with a tab-separated row that names the ``#fields`` in the
input file, as shown earlier.

.. warning::

  The ASCII reader has no notion of file locking, including UNIX’s advisory
  locking. For large files, this means the framework might process a file
  that’s still written to. The reader handles resulting errors robustly (e.g.
  via the reporter log, as described earlier), but nevertheless will encounter
  errors. In order to avoid these problems it’s best to produce a new input
  file on the side, and then atomically rename it to the filename monitored by
  the framework.

There’s currently no JSON ingestion mode for this reader, but see the section
about using the :ref:`raw reader <input-raw-reader>` together with the
builtin :zeek:see:`from_json` function.

The Benchmark Reader
--------------------

The benchmark reader, selected via :zeek:see:`Input::READER_BENCHMARK`, helps
the Zeek developers optimize the speed of the input framework. It can generate
arbitrary amounts of semi-random data in all Zeek data types supported by the
input framework.

The Binary Reader
-----------------

This  reader, selected via :zeek:see:`Input::READER_BINARY`, is intended for
use with file analysis input streams to ingest file content (and is the default
type of reader for those streams).

.. _input-raw-reader:

The Raw Reader
--------------

The raw reader, selected via :zeek:see:`Input::READER_RAW`, reads a file that
is split by a specified record separator (newline by default). The contents are
returned line-by-line as strings; it can, for example, be used to read
configuration files and the like and is probably only useful in the event mode
and not for reading data to tables.

Reading JSON Lines
~~~~~~~~~~~~~~~~~~

.. versionadded:: 6.0


While the ASCII reader does not currently support JSON natively, it is
possible to use the raw reader together with the builtin :zeek:see:`from_json`
function to read files in JSON lines format and instantiate Zeek record
values based on the input.

The following example shows how this can be done, holding two state tables
in order to allow for removal updates of the read data.

.. literalinclude:: denylist.jsonl
   :caption:
   :language: json
   :linenos:
   :tab-width: 4

.. literalinclude:: input_json_1.zeek
   :caption: Loading denylist.jsonl, converting to Zeek types, populating a table.
   :language: zeek
   :linenos:
   :tab-width: 4

If your input data is already in, or can be easily converted into, JSON Lines format
the above approach can be used to load it into Zeek.

.. _input-sqlite-reader:

The SQLite Reader
-----------------

The SQLite input reader, selected via :zeek:see:`Input::READER_SQLITE`,
provides a way to access SQLite databases from Zeek. SQLite is a simple,
file-based, widely used SQL database system. Due to the transactional nature of
SQLite, databases can be used by several applications simultaneously. Hence
they can, for example, be used to make constantly evolving datasets available
to Zeek on a continuous basis.

Reading Data from SQLite Databases
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Like with Zeek’s logging support, reading data from SQLite databases is built
into Zeek without any extra configuration needed. Just like text-based input
readers, the SQLite reader can read data — in this case the result of SQL
queries — into tables or events.

Reading Data into Tables
************************

To read data from a SQLite database, we first have to provide Zeek with the
information how the resulting data will be structured. For this example, we
expect that we have a SQLite database, which contains host IP addresses and the
user accounts that are allowed to log into a specific machine.

The SQLite commands to create the schema are as follows::

  create table machines_to_users (
  host text unique not null,
  users text not null);

  insert into machines_to_users values (
      '192.168.17.1', 'johanna,matthias,seth');
  insert into machines_to_users values (
      '192.168.17.2', 'johanna');
  insert into machines_to_users values (
      '192.168.17.3', 'seth,matthias');

After creating a file called hosts.sqlite with this content, we can read the
resulting table into Zeek:

.. code-block:: zeek

  type Idx: record {
     host: addr;
  };

  type Val: record {
     users: set[string];
  };

  global hostslist: table[addr] of Val = table();

  event zeek_init()
     {
     Input::add_table([$source="/var/db/hosts",
         $name="hosts",
         $idx=Idx,
         $val=Val,
         $destination=hostslist,
         $reader=Input::READER_SQLITE,
         $config=table(["query"] = "select * from machines_to_users;")
         ]);

     Input::remove("hosts");
     }

  event Input::end_of_data(name: string, source: string)
     {
     if ( name != "hosts" )
         return;

     # now all data is in the table
     print "Hosts list has been successfully imported";

     # List the users of one host.
     print hostslist[192.168.17.1]$users;
     }

The ``hostslist`` table can now be used to check host logins against an
available user list.

Turning Data into Events
************************

The second mode is to use the SQLite reader to output the input data as events.
Typically there are two reasons to do this. First, the structure of the input
data is too complicated for a direct table import. In this case, the data can
be read into an event which can then create the necessary data structures in
Zeek in scriptland. Second, the dataset is too big to hold in memory. In this
case, event-driven ingestion can perform checks on-demand.

As an example, let’s consider a large database with malware hashes. Live
database queries allow us to cross-check sporadically occurring downloads
against this evolving database. The SQLite commands to create the schema are as
follows::

  create table malware_hashes (
      hash text unique not null,
      description text not null);

  insert into malware_hashes values ('86f7e437faa5a7fce15d1ddcb9eaeaea377667b8', 'malware a');
  insert into malware_hashes values ('e9d71f5ee7c92d6dc9e92ffdad17b8bd49418f98', 'malware b');
  insert into malware_hashes values ('84a516841ba77a5b4648de2cd0dfcb30ea46dbb4', 'malware c');
  insert into malware_hashes values ('3c363836cf4e16666669a25da280a1865c2d2874', 'malware d');
  insert into malware_hashes values ('58e6b3a414a1e090dfc6029add0f3555ccba127f', 'malware e');
  insert into malware_hashes values ('4a0a19218e082a343a1b17e5333409af9d98f0f5', 'malware f');
  insert into malware_hashes values ('54fd1711209fb1c0781092374132c66e79e2241b', 'malware g');
  insert into malware_hashes values ('27d5482eebd075de44389774fce28c69f45c8a75', 'malware h');
  insert into malware_hashes values ('73f45106968ff8dc51fba105fa91306af1ff6666', 'ftp-trace');

The following code uses the file-analysis framework to get the sha1 hashes of
files that are transmitted over the network. For each hash, a SQL-query runs
against SQLite. If the query returns a result, we output the matching hash.

.. code-block:: zeek

  @load frameworks/files/hash-all-files

  type Val: record {
     hash: string;
     description: string;
  };

  event line(description: Input::EventDescription, tpe: Input::Event, r: Val)
     {
     print fmt("malware-hit with hash %s, description %s", r$hash, r$description);
     }

  global malware_source = "/var/db/malware";

  event file_hash(f: fa_file, kind: string, hash: string)
     {

     # check all sha1 hashes
     if ( kind=="sha1" )
         {
         Input::add_event(
             [
             $source=malware_source,
             $name=hash,
             $fields=Val,
             $ev=line,
             $want_record=T,
             $config=table(
                 ["query"] = fmt("select * from malware_hashes where hash='%s';", hash)
                 ),
             $reader=Input::READER_SQLITE
             ]);
         }
     }

  event Input::end_of_data(name: string, source:string)
     {
     if ( source == malware_source )
         Input::remove(name);
     }

If you run this script against the trace in
:file:`testing/btest/Traces/ftp/ipv4.trace`, you will get one hit.
