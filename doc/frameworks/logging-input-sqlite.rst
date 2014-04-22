
============================================
Logging To and Reading From SQLite Databases
============================================

.. rst-class:: opening

   Starting with version 2.2, Bro features a SQLite logging writer
   as well as a SQLite input reader. SQLite is a simple, file-based,
   widely used SQL database system. Using SQLite allows Bro to write
   and access data in a format that is easy to use in interchange with
   other applications. Due to the transactional nature of SQLite,
   databases can be used by several applications simultaneously. Hence,
   they can, for example, be used to make data that changes regularly available
   to Bro on a continuing basis.

.. contents::

Warning
=======

In contrast to the ASCII reader and writer, the SQLite plugins have not yet
seen extensive use in production environments. While we are not aware
of any issues with them, we urge to caution when using them
in production environments. There could be lingering issues which only occur
when the plugins are used with high amounts of data or in high-load environments.

Logging Data into SQLite Databases
==================================

Logging support for SQLite is available in all Bro installations starting with
version 2.2. There is no need to load any additional scripts or for any compile-time
configurations.

Sending data from existing logging streams to SQLite is rather straightforward. You
have to define a filter which specifies SQLite as the writer.

The following example code adds SQLite as a filter for the connection log:

.. btest-include:: ${DOC_ROOT}/frameworks/sqlite-conn-filter.bro

.. btest:: sqlite-conn-filter-check

    # Make sure this parses correctly at least.
    @TEST-EXEC: bro ${DOC_ROOT}/frameworks/sqlite-conn-filter.bro

Bro will create the database file ``/var/db/conn.sqlite``, if it does not already exist.
It will also create a table with the name ``conn`` (if it does not exist) and start
appending connection information to the table.

At the moment, SQLite databases are not rotated the same way ASCII log-files are. You
have to take care to create them in an adequate location.

If you examine the resulting SQLite database, the schema will contain the same fields
that are present in the ASCII log files::

    # sqlite3 /var/db/conn.sqlite

    SQLite version 3.8.0.2 2013-09-03 17:11:13
    Enter ".help" for instructions
    Enter SQL statements terminated with a ";"
    sqlite> .schema
    CREATE TABLE conn (
    'ts' double precision,
    'uid' text,
    'id.orig_h' text,
    'id.orig_p' integer,
    ...

Note that the ASCII ``conn.log`` will still be created. To disable the ASCII writer for a
log stream, you can remove the default filter:

.. code:: bro

    Log::remove_filter(Conn::LOG, "default");


To create a custom SQLite log file, you have to create a new log stream that contains
just the information you want to commit to the database. Please refer to the
:ref:`framework-logging` documentation on how to create custom log streams.

Reading Data from SQLite Databases
==================================

Like logging support, support for reading data from SQLite databases is built into Bro starting
with version 2.2.

Just as with the text-based input readers (please refer to the :ref:`framework-input`
documentation for them and for basic information on how to use the input-framework), the SQLite reader
can be used to read data - in this case the result of SQL queries - into tables or into events.

Reading Data into Tables
------------------------

To read data from a SQLite database, we first have to provide Bro with the information, how
the resulting data will be structured. For this example, we expect that we have a SQLite database,
which contains host IP addresses and the user accounts that are allowed to log into a specific
machine.

The SQLite commands to create the schema are as follows::

    create table machines_to_users (
    host text unique not null,
    users text not null);

    insert into machines_to_users values ('192.168.17.1', 'bernhard,matthias,seth');
    insert into machines_to_users values ('192.168.17.2', 'bernhard');
    insert into machines_to_users values ('192.168.17.3', 'seth,matthias');

After creating a file called ``hosts.sqlite`` with this content, we can read the resulting table
into Bro:

.. btest-include:: ${DOC_ROOT}/frameworks/sqlite-read-table.bro

.. btest:: sqlite-read-table-check

    # Make sure this parses correctly at least.
    @TEST-EXEC: bro ${DOC_ROOT}/frameworks/sqlite-read-table.bro

Afterwards, that table can be used to check logins into hosts against the available
userlist.

Turning Data into Events
------------------------

The second mode is to use the SQLite reader to output the input data as events. Typically there
are two reasons to do this. First, when the structure of the input data is too complicated
for a direct table import. In this case, the data can be read into an event which can then
create the necessary data structures in Bro in scriptland.

The second reason is, that the dataset is too big to hold it in memory. In this case, the checks
can be performed on-demand, when Bro encounters a situation where it needs additional information.

An example for this would be an internal huge database with malware hashes. Live database queries
could be used to check the sporadically happening downloads against the database.

The SQLite commands to create the schema are as follows::

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


The following code uses the file-analysis framework to get the sha1 hashes of files that are
transmitted over the network. For each hash, a SQL-query is run against SQLite. If the query
returns with a result, we had a hit against our malware-database and output the matching hash.

.. btest-include:: ${DOC_ROOT}/frameworks/sqlite-read-events.bro

.. btest:: sqlite-read-events-check

    # Make sure this parses correctly at least.
    @TEST-EXEC: bro ${DOC_ROOT}/frameworks/sqlite-read-events.bro

If you run this script against the trace in ``testing/btest/Traces/ftp/ipv4.trace``, you
will get one hit.
