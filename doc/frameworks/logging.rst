
.. _framework-logging:

=================
Logging Framework
=================

.. rst-class:: opening

   Bro comes with a flexible key-value based logging interface that
   allows fine-grained control of what gets logged and how it is
   logged. This document describes how logging can be customized and
   extended.

.. contents::

Terminology
===========

Bro's logging interface is built around three main abstractions:

    Streams
        A log stream corresponds to a single log. It defines the set of
        fields that a log consists of with their names and types.
        Examples are the ``conn`` stream for recording connection summaries,
        and the ``http`` stream for recording HTTP activity.

    Filters
        Each stream has a set of filters attached to it that determine
        what information gets written out. By default, each stream has
        one default filter that just logs everything directly to disk.
        However, additional filters can be added to record only a subset
        of the log records, write to different outputs, or set a custom
        rotation interval.  If all filters are removed from a stream,
        then output is disabled for that stream.

    Writers
        Each filter has a writer.  A writer defines the actual output
        format for the information being logged. The default writer is
        the ASCII writer, which produces tab-separated ASCII files. Other
        writers are available, like for binary output or direct logging
        into a database.

There are several different ways to customize Bro's logging: you can create
a new log stream, you can extend an existing log with new fields, you
can apply filters to an existing log stream, or you can customize the output
format by setting log writer options.  All of these approaches are
described in this document.

Streams
=======

In order to log data to a new log stream, all of the following needs to be
done:

- A :bro:type:`record` type must be defined which consists of all the
  fields that will be logged (by convention, the name of this record type is
  usually "Info").
- A log stream ID (an :bro:type:`enum` with type name "Log::ID") must be
  defined that uniquely identifies the new log stream.
- A log stream must be created using the :bro:id:`Log::create_stream` function.
- When the data to be logged becomes available, the :bro:id:`Log::write`
  function must be called.

In the following example, we create a new module "Foo" which creates
a new log stream.

.. code:: bro

    module Foo;

    export {
        # Create an ID for our new stream. By convention, this is
        # called "LOG".
        redef enum Log::ID += { LOG };

        # Define the record type that will contain the data to log.
        type Info: record {
            ts: time        &log;
            id: conn_id     &log;
            service: string &log &optional;
            missed_bytes: count &log &default=0;
        };
    }

    # Optionally, we can add a new field to the connection record so that
    # the data we are logging (our "Info" record) will be easily
    # accessible in a variety of event handlers.
    redef record connection += {
        # By convention, the name of this new field is the lowercase name
        # of the module.
        foo: Info &optional;
    };

    # This event is handled at a priority higher than zero so that if
    # users modify this stream in another script, they can do so at the
    # default priority of zero.
    event bro_init() &priority=5
        {
        # Create the stream. This adds a default filter automatically.
        Log::create_stream(Foo::LOG, [$columns=Info, $path="foo"]);
        }

In the definition of the "Info" record above, notice that each field has the
:bro:attr:`&log` attribute.  Without this attribute, a field will not appear in
the log output. Also notice one field has the :bro:attr:`&optional` attribute.
This indicates that the field might not be assigned any value before the
log record is written.  Finally, a field with the :bro:attr:`&default`
attribute has a default value assigned to it automatically.

At this point, the only thing missing is a call to the :bro:id:`Log::write`
function to send data to the logging framework.  The actual event handler
where this should take place will depend on where your data becomes available.
In this example, the :bro:id:`connection_established` event provides our data,
and we also store a copy of the data being logged into the
:bro:type:`connection` record:

.. code:: bro

    event connection_established(c: connection)
        {
        local rec: Foo::Info = [$ts=network_time(), $id=c$id];

        # Store a copy of the data in the connection record so other
        # event handlers can access it.
        c$foo = rec;

        Log::write(Foo::LOG, rec);
        }

If you run Bro with this script, a new log file ``foo.log`` will be created.
Although we only specified four fields in the "Info" record above, the
log output will actually contain seven fields because one of the fields
(the one named "id") is itself a record type.  Since a :bro:type:`conn_id`
record has four fields, then each of these fields is a separate column in
the log output.  Note that the way that such fields are named in the log
output differs slightly from the way we would refer to the same field
in a Bro script (each dollar sign is replaced with a period).  For example,
to access the first field of a ``conn_id`` in a Bro script we would use
the notation ``id$orig_h``, but that field is named ``id.orig_h``
in the log output.

When you are developing scripts that add data to the :bro:type:`connection`
record, care must be given to when and how long data is stored.
Normally data saved to the connection record will remain there for the
duration of the connection and from a practical perspective it's not
uncommon to need to delete that data before the end of the connection.


Add Fields to a Log
-------------------

You can add additional fields to a log by extending the record
type that defines its content, and setting a value for the new fields
before each log record is written.

Let's say we want to add a boolean field ``is_private`` to
:bro:type:`Conn::Info` that indicates whether the originator IP address
is part of the :rfc:`1918` space:

.. code:: bro

    # Add a field to the connection log record.
    redef record Conn::Info += {
        ## Indicate if the originator of the connection is part of the
        ## "private" address space defined in RFC1918.
        is_private: bool &default=F &log;
    };

As this example shows, when extending a log stream's "Info" record, each
new field must always be declared either with a ``&default`` value or
as ``&optional``.  Furthermore, you need to add the ``&log`` attribute
or otherwise the field won't appear in the log file.

Now we need to set the field.  Although the details vary depending on which
log is being extended, in general it is important to choose a suitable event
in which to set the additional fields because we need to make sure that
the fields are set before the log record is written.  Sometimes the right
choice is the same event which writes the log record, but at a higher
priority (in order to ensure that the event handler that sets the additional
fields is executed before the event handler that writes the log record).

In this example, since a connection's summary is generated at
the time its state is removed from memory, we can add another handler
at that time that sets our field correctly:

.. code:: bro

    event connection_state_remove(c: connection)
        {
        if ( c$id$orig_h in Site::private_address_space )
            c$conn$is_private = T;
        }

Now ``conn.log`` will show a new field ``is_private`` of type
``bool``.  If you look at the Bro script which defines the connection
log stream :doc:`/scripts/base/protocols/conn/main.bro`, you will see
that ``Log::write`` gets called in an event handler for the
same event as used in this example to set the additional fields, but at a
lower priority than the one used in this example (i.e., the log record gets
written after we assign the ``is_private`` field).

For extending logs this way, one needs a bit of knowledge about how
the script that creates the log stream is organizing its state
keeping. Most of the standard Bro scripts attach their log state to
the :bro:type:`connection` record where it can then be accessed, just
like ``c$conn`` above. For example, the HTTP analysis adds a field
``http`` of type :bro:type:`HTTP::Info` to the :bro:type:`connection`
record.


Define a Logging Event
----------------------

Sometimes it is helpful to do additional analysis of the information
being logged. For these cases, a stream can specify an event that will
be generated every time a log record is written to it.  To do this, we
need to modify the example module shown above to look something like this:

.. code:: bro

    module Foo;

    export {
        redef enum Log::ID += { LOG };

        type Info: record {
            ts: time     &log;
            id: conn_id  &log;
            service: string &log &optional;
            missed_bytes: count &log &default=0;
        };

        # Define a logging event. By convention, this is called
        # "log_<stream>".
        global log_foo: event(rec: Info);
    }

    event bro_init() &priority=5
        {
        # Specify the "log_foo" event here in order for Bro to raise it.
        Log::create_stream(Foo::LOG, [$columns=Info, $ev=log_foo,
                           $path="foo"]);
        }

All of Bro's default log streams define such an event. For example, the
connection log stream raises the event :bro:id:`Conn::log_conn`. You
could use that for example for flagging when a connection to a
specific destination exceeds a certain duration:

.. code:: bro

    redef enum Notice::Type += {
        ## Indicates that a connection remained established longer
        ## than 5 minutes.
        Long_Conn_Found
    };

    event Conn::log_conn(rec: Conn::Info)
        {
        if ( rec?$duration && rec$duration > 5mins )
            NOTICE([$note=Long_Conn_Found,
                    $msg=fmt("unusually long conn to %s", rec$id$resp_h),
                    $id=rec$id]);
        }

Often, these events can be an alternative to post-processing Bro logs
externally with Perl scripts. Much of what such an external script
would do later offline, one may instead do directly inside of Bro in
real-time.

Disable a Stream
----------------

One way to "turn off" a log is to completely disable the stream.  For
example, the following example will prevent the conn.log from being written:

.. code:: bro

    event bro_init()
        {
        Log::disable_stream(Conn::LOG);
        }

Note that this must run after the stream is created, so the priority
of this event handler must be lower than the priority of the event handler
where the stream was created.


Filters
=======

A stream has one or more filters attached to it (a stream without any filters
will not produce any log output).  When a stream is created, it automatically
gets a default filter attached to it.  This default filter can be removed
or replaced, or other filters can be added to the stream.  This is accomplished
by using either the :bro:id:`Log::add_filter` or :bro:id:`Log::remove_filter`
function.  This section shows how to use filters to do such tasks as
rename a log file, split the output into multiple files, control which
records are written, and set a custom rotation interval.

Rename Log File
---------------

Normally, the log filename for a given log stream is determined when the
stream is created, unless you explicitly specify a different one by adding
a filter.

The easiest way to change a log filename is to simply replace the
default log filter with a new filter that specifies a value for the "path"
field.  In this example, "conn.log" will be changed to "myconn.log":

.. code:: bro

    event bro_init()
        {
        # Replace default filter for the Conn::LOG stream in order to
        # change the log filename.

        local f = Log::get_filter(Conn::LOG, "default");
        f$path = "myconn";
        Log::add_filter(Conn::LOG, f);
        }

Keep in mind that the "path" field of a log filter never contains the
filename extension.  The extension will be determined later by the log writer.

Add a New Log File
------------------

Normally, a log stream writes to only one log file.  However, you can
add filters so that the stream writes to multiple files.  This is useful
if you want to restrict the set of fields being logged to the new file.

In this example, a new filter is added to the Conn::LOG stream that writes
two fields to a new log file:

.. code:: bro

    event bro_init()
        {
        # Add a new filter to the Conn::LOG stream that logs only
        # timestamp and originator address.

        local filter: Log::Filter = [$name="orig-only", $path="origs",
                                     $include=set("ts", "id.orig_h")];
        Log::add_filter(Conn::LOG, filter);
        }


Notice how the "include" filter attribute specifies a set that limits the
fields to the ones given. The names correspond to those in the
:bro:type:`Conn::Info` record (however, because the "id" field is itself a
record, we can specify an individual field of "id" by the dot notation
shown in the example).

Using the code above, in addition to the regular ``conn.log``, you will
now also get a new log file ``origs.log`` that looks like the regular
``conn.log``, but will have only the fields specified in the "include"
filter attribute.

If you want to skip only some fields but keep the rest, there is a
corresponding ``exclude`` filter attribute that you can use instead of
``include`` to list only the ones you are not interested in.

If you want to make this the only log file for the stream, you can
remove the default filter:

.. code:: bro

    event bro_init()
        {
        # Remove the filter called "default".
        Log::remove_filter(Conn::LOG, "default");
        }

Determine Log Path Dynamically
------------------------------

Instead of using the "path" filter attribute, a filter can determine
output paths *dynamically* based on the record being logged. That
allows, e.g., to record local and remote connections into separate
files. To do this, you define a function that returns the desired path,
and use the "path_func" filter attribute:

.. code:: bro

    # Note: if using BroControl then you don't need to redef local_nets.
    redef Site::local_nets = { 192.168.0.0/16 };

    function myfunc(id: Log::ID, path: string, rec: Conn::Info) : string
        {
        # Return "conn-local" if originator is a local IP, otherwise
        # return "conn-remote".
        local r = Site::is_local_addr(rec$id$orig_h) ? "local" : "remote";
        return fmt("%s-%s", path, r);
        }

    event bro_init()
        {
        local filter: Log::Filter = [$name="conn-split",
                 $path_func=myfunc, $include=set("ts", "id.orig_h")];
        Log::add_filter(Conn::LOG, filter);
        }

Running this will now produce two new files, ``conn-local.log`` and
``conn-remote.log``, with the corresponding entries (for this example to work,
the ``Site::local_nets`` must specify your local network). One could extend
this further for example to log information by subnets or even by IP
address. Be careful, however, as it is easy to create many files very
quickly.

The ``myfunc`` function has one drawback: it can be used
only with the :bro:enum:`Conn::LOG` stream as the record type is hardcoded
into its argument list. However, Bro allows to do a more generic
variant:

.. code:: bro

    function myfunc(id: Log::ID, path: string,
                    rec: record { id: conn_id; } ) : string
        {
        local r = Site::is_local_addr(rec$id$orig_h) ? "local" : "remote";
        return fmt("%s-%s", path, r);
        }

This function can be used with all log streams that have records
containing an ``id: conn_id`` field.

Filter Log Records
------------------

We have seen how to customize the columns being logged, but
you can also control which records are written out by providing a
predicate that will be called for each log record:

.. code:: bro

    function http_only(rec: Conn::Info) : bool
        {
        # Record only connections with successfully analyzed HTTP traffic
        return rec?$service && rec$service == "http";
        }

    event bro_init()
        {
        local filter: Log::Filter = [$name="http-only", $path="conn-http",
                                     $pred=http_only];
        Log::add_filter(Conn::LOG, filter);
        }

This will result in a new log file ``conn-http.log`` that contains only
the log records from ``conn.log`` that are analyzed as HTTP traffic.

Rotation
--------

The log rotation interval is globally controllable for all
filters by redefining the :bro:id:`Log::default_rotation_interval` option
(note that when using BroControl, this option is set automatically via
the BroControl configuration).

Or specifically for certain :bro:type:`Log::Filter` instances by setting
their ``interv`` field.  Here's an example of changing just the
:bro:enum:`Conn::LOG` stream's default filter rotation.

.. code:: bro

    event bro_init()
        {
        local f = Log::get_filter(Conn::LOG, "default");
        f$interv = 1 min;
        Log::add_filter(Conn::LOG, f);
        }

Writers
=======

Each filter has a writer.  If you do not specify a writer when adding a
filter to a stream, then the ASCII writer is the default.

There are two ways to specify a non-default writer.  To change the default
writer for all log filters, just redefine the :bro:id:`Log::default_writer`
option.  Alternatively, you can specify the writer to use on a per-filter
basis by setting a value for the filter's "writer" field.  Consult the
documentation of the writer to use to see if there are other options that are
needed.

ASCII Writer
------------

By default, the ASCII writer outputs log files that begin with several
lines of metadata, followed by the actual log output.  The metadata
describes the format of the log file, the "path" of the log (i.e., the log
filename without file extension), and also specifies the time that the log
was created and the time when Bro finished writing to it.
The ASCII writer has a number of options for customizing the format of its
output, see :doc:`/scripts/base/frameworks/logging/writers/ascii.bro`.
If you change the output format options, then be careful to check whether
your postprocessing scripts can still recognize your log files.

Some writer options are global (i.e., they affect all log filters using
that log writer).  For example, to change the output format of all ASCII
logs to JSON format:

.. code:: bro

    redef LogAscii::use_json = T;

Some writer options are filter-specific (i.e., they affect only the filters
that explicitly specify the option).  For example, to change the output
format of the ``conn.log`` only:

.. code:: bro

    event bro_init()
        {
        local f = Log::get_filter(Conn::LOG, "default");
        # Use tab-separated-value mode
        f$config = table(["tsv"] = "T");
        Log::add_filter(Conn::LOG, f);
        }


Other Writers
-------------

Bro supports the following additional built-in output formats:

.. toctree::
   :maxdepth: 1

   logging-input-sqlite

Additional writers are available as external plugins:

.. toctree::
   :maxdepth: 1

   ../components/bro-plugins/dataseries/README
   ../components/bro-plugins/elasticsearch/README

