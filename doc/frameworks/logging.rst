
.. _framework-logging:

=================
Logging Framework
=================

Zeek comes with a flexible logging interface that allows fine-grained control of
what gets logged and how it is logged. This section explains how you can use
this framework to customize and extended your logs.

Terminology
===========

Zeek’s logging interface is built around three main abstractions:

  Streams
    A log stream corresponds to a single log. It defines the set of fields that
    a log consists of with their names and types. Examples are the conn stream
    for recording connection summaries, and the http stream for recording HTTP
    activity.

  Filters
    Each stream has a set of filters attached to it that determine what
    information gets written out, and how. By default, each stream has one
    default filter that just logs everything directly to disk. However,
    additional filters can be added to record only a subset of the log records,
    write to different outputs, or set a custom rotation interval. If all
    filters are removed from a stream, then output is disabled for that stream.

  Writers
    Each filter has a writer. A writer defines the actual output format for the
    information being logged. The default writer is the ASCII writer, which
    produces tab-separated ASCII files. Other writers are available, like for
    binary output or direct logging into a database.

There are several different ways to customize Zeek’s logging: you can create a
new log stream, you can extend an existing log with new fields, you can apply
filters to an existing log stream, or you can customize the output format by
setting log writer options. All of these approaches are described below.

Streams
=======

In order to log data to a new log stream, all of the following needs to be done:

* A :zeek:see:`record` type must be defined which consists of all the fields
  that will be logged (by convention, the name of this record type is usually
  “Info”).
* A log stream ID (an :zeek:see:`enum` with type name :zeek:see:`Log::ID`) must
  be defined that uniquely identifies the new log stream.
* A log stream must be created using the :zeek:see:`Log::create_stream`
  function.
* When the data to be logged becomes available, the :zeek:see:`Log::write`
  function must be called.

In the following example, we create a new module, ``Foo``, which creates a new
log stream.

.. code-block:: zeek

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
  event zeek_init() &priority=5
      {
      # Create the stream. This adds a default filter automatically.
      Log::create_stream(Foo::LOG, [$columns=Info, $path="foo"]);
      }

In the definition of the ``Info`` record above, notice that each field has the
:zeek:see:`&log` attribute. Without this attribute, a field will not appear in
the log output. Also notice one field has the :zeek:see:`&optional` attribute.
This indicates that the field might not be assigned any value before the log
record is written.  Finally, a field with the :zeek:see:`&default` attribute
has a default value assigned to it automatically.

At this point, the only thing missing is a call to the :zeek:see:`Log::write`
function to send data to the logging framework. The actual event handler where
this should take place will depend on where your data becomes available. In
this example, the :zeek:see:`connection_established` event provides our data,
and we also store a copy of the data being logged into the
:zeek:see:`connection` record:

.. code-block:: zeek

  event connection_established(c: connection)
      {
      local rec: Foo::Info = [$ts=network_time(), $id=c$id];

      # Store a copy of the data in the connection record so other
      # event handlers can access it.
      c$foo = rec;

      Log::write(Foo::LOG, rec);
      }

If you run Zeek with this script, a new log file :file:`foo.log` will be
created.  Although we only specified four fields in the ``Info`` record above,
the log output will actually contain seven fields because one of the fields
(the one named ``id``) is itself a record type. Since a :zeek:see:`conn_id`
record has four fields, then each of these fields is a separate column in the
log output. Note that the way that such fields are named in the log output
differs slightly from the way we would refer to the same field in a Zeek script
(each dollar sign is replaced with a period). For example, to access the first
field of a :zeek:see:`conn_id` in a Zeek script we would use the notation
``id$orig_h``, but that field is named ``id.orig_h`` in the log output.

When you are developing scripts that add data to the :zeek:see:`connection`
record, care must be given to when and how long data is stored. Normally data
saved to the connection record will remain there for the duration of the
connection and from a practical perspective it’s not uncommon to need to delete
that data before the end of the connection.

Add Fields to a Log
-------------------

You can add additional fields to a log by extending the record type that
defines its content, and setting a value for the new fields before each log
record is written.

Let’s say we want to add a boolean field ``is_private`` to
:zeek:see:`Conn::Info` that indicates whether the originator IP address is part
of the :rfc:`1918` space:

.. code-block:: zeek

  # Add a field to the connection log record.
  redef record Conn::Info += {
      ## Indicate if the originator of the connection is part of the
      ## "private" address space defined in RFC1918.
      is_private: bool &default=F &log;
  };

As this example shows, when extending a log stream’s ``Info`` record, each new
field must always be declared either with a &default value or as
:zeek:see:`&optional`.  Furthermore, you need to add the :zeek:see:`&log`
attribute or otherwise the field won’t appear in the log file.

Now we need to set the field. Although the details vary depending on which log
is being extended, in general it is important to choose a suitable event in
which to set the additional fields because we need to make sure that the fields
are set before the log record is written. Sometimes the right choice is the
same event which writes the log record, but at a higher priority (in order to
ensure that the event handler that sets the additional fields is executed
before the event handler that writes the log record).

In this example, since a connection’s summary is generated at the time its
state is removed from memory, we can add another handler at that time that sets
our field correctly:

.. code-block:: zeek

  event connection_state_remove(c: connection)
      {
      if ( c$id$orig_h in Site::private_address_space )
          c$conn$is_private = T;
      }

Now :file:`conn.log` will show a new field ``is_private`` of type
:zeek:see:`bool`. If you look at the Zeek script which defines the connection
log stream :doc:`/scripts/base/protocols/conn/main.zeek`, you will see that
:zeek:see:`Log::write` gets called in an event handler for the same event as
used in this example to set the additional fields, but at a lower priority than
the one used in this example (i.e., the log record gets written after we assign
the ``is_private`` field).

For extending logs this way, one needs a bit of knowledge about how the script
that creates the log stream is organizing its state keeping. Most of the
standard Zeek scripts attach their log state to the :zeek:see:`connection`
record where it can then be accessed, just like ``c$conn`` above. For example,
the HTTP analysis adds a field http of type :zeek:see:`HTTP::Info` to the
:zeek:see:`connection` record.

Define a Logging Event
----------------------

Sometimes it is helpful to do additional analysis of the information being
logged. For these cases, a stream can specify an event that will be generated
every time a log record is written to it. To do this, we need to modify the
example module shown above to look something like this:

.. code-block:: zeek

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

  event zeek_init() &priority=5
      {
      # Specify the "log_foo" event here in order for Zeek to raise it.
      Log::create_stream(Foo::LOG, [$columns=Info, $ev=log_foo,
                         $path="foo"]);
      }

All of Zeek’s default log streams define such an event. For example, the
connection log stream raises the event :zeek:see:`Conn::log_conn`. You could
use that for example for flagging when a connection to a specific destination
exceeds a certain duration:

.. code-block:: zeek

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

Often, these events can be an alternative to post-processing Zeek logs
externally with Perl scripts. Much of what such an external script would do
later offline, one may instead do directly inside of Zeek in real-time.

Disable a Stream
----------------

One way to “turn off” a log is to completely disable the stream. For example,
the following example will prevent the :file:`conn.log` from being written:

.. code-block:: zeek

  event zeek_init()
      {
      Log::disable_stream(Conn::LOG);
      }

Note that this must run after the stream is created, so the priority of this
event handler must be lower than the priority of the event handler where the
stream was created.


Delaying Log Writes
-------------------

.. versionadded:: 6.2

The logging framework allows delaying log writes using the
:zeek:see:`Log::delay` function.

This functionality enables querying or waiting for additional data to attach to
an in-flight log record for which a :zeek:see:`Log::write` has happened.
Common examples are the execution of DNS reverse lookups for the addresses
of a connection, or - more generally - asynchronous queries to external systems.
Similarly, waiting a small duration for more data from an external process
pertaining to specific connections or events is another. For example, endpoint
agents may provide detailed process information for specific connections
logged by Zeek.

Conceptually, the delay of a log record is placed after the execution of the
global :zeek:see:`Log::log_stream_policy` hook and before the execution of
:ref:`policy hooks attached to filters <logging-filtering-log-records>`.
At this point, calling :zeek:see:`Log::delay` is only valid for the currently
*active write* during the execution of the global :zeek:see:`Log::log_stream_policy`
hook. Calling :zeek:see:`Log::delay` in any other context or with the wrong
arguments results in runtime errors.

.. note::

   While this may appear very restrictive, it does make it explicit that it is
   the action of a :zeek:see:`Log::write` for a given stream and log record
   that is being delayed as well as providing a defined point where a delay starts.

   Prior ideas entertained the idea of an implicit and very lax interface, but
   in the end was deemed too loose and provided too much flexibility that would
   be hard to later restrict again or keep stable. The current interface might
   be made more lax in the future if it turns out to be too rigid.


By default, log records are not delayed. That is, during the execution of
the :zeek:see:`Log::write` function, a serialized version of the given log
record is handed off to a remote logger or a local logging thread.
Modifications of the same log record after :zeek:see:`Log::write` has returned
have no effect.

In contrast, when a log write is delayed using the :zeek:see:`Log::delay`
function, the record is enqueued into a per-stream record queue and the
:zeek:see:`Log::write` returns. Processing of the delayed write resumes once
it is released by using the :zeek:see:`Log::delay_finish` function or until
a maximum, per-stream configurable, delay duration expires.

When processing of a log write is resumed, first, all post delay callbacks
given to :zeek:see:`Log::delay` are executed. Thereafter, as for non-delayed
writes, filter policy hooks are executed and the log record is serialized.

Policy hooks attached to filters and the serialization step observe any
mutations done during the delay. Filter policy hooks may even use these
modifications for deciding on the verdict of the given log record.

.. note::

   Policy hooks attached to filters are often used to skip logging of
   uninteresting log records. When combined with log write delaying, users
   should consider lifting such filter logic up into the
   :zeek:see:`Log::log_stream_policy` hook to avoid unnecessarily delaying
   records when it is known that these will be discarded later on.


The :zeek:see:`Log::delay` and :zeek:see:`Log::delay_finish` functions increment
and decrement an internal reference count for a given write. To continue a
delayed write, :zeek:see:`Log::delay_finish` must be called as often as
:zeek:see:`Log::delay`.


Zeek delays a log record by a configurable interval defined for each log stream.
It defaults to the global :zeek:see:`Log::default_max_delay_interval`, and can be
adapted by calling :zeek:see:`Log::set_max_delay_interval` on the stream.
It is possible to explicitly extend the delay duration by providing a post
delay callback to :zeek:see:`Log::delay`. Calling :zeek:see:`Log::delay` from
within such a post delay callback re-delays the record, essentially putting
it at the end of the per-stream queue again.

.. note::

   While this puts additional burden on the script writer to realize per-record
   specific longer delay intervals, it allows for a simpler internal implementation.
   Additionally, the explicit re-delaying is also meant to make users aware of the
   consequences when using such long delays either on purpose or by accident.

   For multiple second or even longer delays, it is suggested to consider resumable,
   robust and non-ephemeral external post processing steps based on Zeek logs instead.
   In the face of worker crashes or uncontrolled restarts of a Zeek cluster, all
   delayed log records are inevitably lost.


The following example shows how to use the :ref:`when <when-statement>` to asynchronously
lookup the DNS names of the originator and responder addresses to enrich an
in-flight :zeek:see:`Conn::Info` record. By default, a stream's maximum delay
interval is 200 milliseconds - the ``timeout 150msec`` part ensures a delayed
write resumes after 150 milliseconds already by explicitly calling
:zeek:see:`Log::delay_finish`.


.. literalinclude:: logging/delay1.zeek
   :caption: Enriching conn.log with originator and responder names.
   :language: zeek
   :linenos:
   :tab-width: 4


Filters
=======

A stream has one or more filters attached to it. A stream without any filters
will not produce any log output. Filters govern two aspects of log production:
they control which of the stream’s log entries get written out, and they define
how to actually implement the log writes. They do the latter by specifying a
log writer that implements the write operation, such as the ASCII writer (see
below) for text file output. When a stream is created, it automatically gets a
default filter attached to it. This default filter can be removed or replaced,
or other filters can be added to the stream. This is accomplished by using
either the :zeek:see:`Log::add_filter` or :zeek:see:`Log::remove_filter`
function. This section shows how to use filters to do such tasks as rename a
log file, split the output into multiple files, control which records are
written, and set a custom rotation interval.

Each filter has a unique name, scoped to the stream it belongs to. That is, all
filters attached to a given stream have different names. Calling
:zeek:see:`Log::add_filter` to add a filter with a name that already exists for
the stream replaces the existing filter.

Rename a Log File
-----------------

Normally, the log filename for a given log stream is determined when the stream
is created, unless you explicitly specify a different one by adding a filter.

The easiest way to change a log filename is to simply replace the default log
filter with a new filter that specifies a value for the ``path`` field. In this
example, :file:`conn.log` will be changed to :file:`myconn.log`:

.. code-block:: zeek

  event zeek_init()
      {
      # Replace default filter for the Conn::LOG stream in order to
      # change the log filename.

      local f = Log::get_filter(Conn::LOG, "default");
      f$path = "myconn";
      Log::add_filter(Conn::LOG, f);
      }

Keep in mind that the ``path`` field of a log filter never contains the
filename extension. The extension will be determined later by the log writer.

Change the Logging Directory
----------------------------

By default, Zeek log files are created in the current working directory.
To write logs into a different directory, set :zeek:see:`Log::default_logdir`:

.. code-block:: zeek

  redef Log::default_logdir = /path/to/output_log_directory

The :zeek:see:`Log::default_logdir` option is honored by all file based
writes included with Zeek (ASCII and SQLite).

Add an Additional Output File
-----------------------------

Normally, a log stream writes to only one log file. However, you can add
filters so that the stream writes to multiple files. This is useful if you want
to restrict the set of fields being logged to the new file.

In this example, a new filter is added to the :zeek:see:`Conn::LOG` stream that
writes two fields to a new log file:

.. code-block:: zeek

  event zeek_init()
      {
      # Add a new filter to the Conn::LOG stream that logs only
      # timestamp and originator address.

      local filter: Log::Filter = [$name="orig-only", $path="origs",
                                   $include=set("ts", "id.orig_h")];
      Log::add_filter(Conn::LOG, filter);
      }

.. note::

  When multiple filters added to a stream use the same path value, Zeek will
  disambiguate the output file names by adding numeric suffixes to the name. If
  we say ``$path="conn"`` in the above example, Zeek warns us about the fact that
  it’ll write this filter’s log entries to a different file::

    1071580905.346457 warning: Write using filter 'orig-only' on path 'conn' changed to use new path 'conn-2' to avoid conflict with filter 'default'

  The same also happens when omitting a path value, in which case the filter
  inherits the value of the stream’s path member.

Notice how the ``include`` filter attribute specifies a set that limits the
fields to the ones given. The names correspond to those in the
:zeek:see:`Conn::Info` record (however, because the ``id`` field is itself a
record, we can specify an individual field of ``id`` by the dot notation shown
in the example).

Using the code above, in addition to the regular :file:`conn.log`, you will now
also get a new log file :file:`origs.log` that looks like the regular
:file:`conn.log`, but will have only the fields specified in the ``include``
filter attribute.

If you want to skip only some fields but keep the rest, there is a
corresponding exclude filter attribute that you can use instead of include to
list only the ones you are not interested in.

If you want to make this the only log file for the stream, you can remove the
default filter:

.. code-block:: zeek

  event zeek_init()
      {
      # Remove the filter called "default".
      Log::remove_filter(Conn::LOG, "default");
      }

Determine Log Path Dynamically
------------------------------

Instead of using the ``path`` filter attribute, a filter can determine output
paths *dynamically* based on the record being logged. That allows, e.g., to
record local and remote connections into separate files. To do this, you define
a function that returns the desired path, and use the ``path_func`` filter
attribute:

.. code-block:: zeek

  function myfunc(id: Log::ID, path: string, rec: Conn::Info) : string
      {
      # Return "conn-local" if originator is a local IP, otherwise
      # return "conn-remote".
      local r = Site::is_local_addr(rec$id$orig_h) ? "local" : "remote";
      return fmt("%s-%s", path, r);
      }

  event zeek_init()
      {
      local filter: Log::Filter = [$name="conn-split",
               $path_func=myfunc, $include=set("ts", "id.orig_h")];
      Log::add_filter(Conn::LOG, filter);
      }

Running this will now produce two new files, :file:`conn-local.log` and
:file:`conn-remote.log`, with the corresponding entries. For this example
to work, :zeek:see:`Site::local_nets` must specify your local network.
It defaults to IANA's standard private address space. One
could extend this further for example to log information by subnets or even by
IP address. Be careful, however, as it is easy to create many files very
quickly.

The ``myfunc`` function has one drawback: it can be used only with the :zeek:see:`Conn::LOG`
stream as the record type is hardcoded into its argument list. However, Zeek
allows to do a more generic variant:

.. code-block:: zeek

  function myfunc(id: Log::ID, path: string,
                  rec: record { id: conn_id; } ) : string
      {
      local r = Site::is_local_addr(rec$id$orig_h) ? "local" : "remote";
      return fmt("%s-%s", path, r);
      }

This function can be used with all log streams that have records containing an
``id: conn_id`` field.

.. _logging-filtering-log-records:

Filtering Log Records
---------------------

We just saw ways how to customize the logged columns. The logging framework also
lets you control which records Zeek writes out. It relies on Zeek’s :zeek:see:`hook`
mechanism to do this, as follows. The framework provides two levels of "policy"
hooks, a global one and a set of filter-level ones. The hook handlers can
implement additional processing of a log record, including vetoing the writing
of the record.  Any handler that uses a :zeek:see:`break` statement to leave the
hook declares that a record shall not be written out. Anyone can attach handlers
to these hooks, which look as follows:

.. code-block:: zeek

  type Log::StreamPolicyHook: hook(rec: any, id: ID);
  type Log::PolicyHook: hook(rec: any, id: ID, filter: Filter);

For both hook types, the ``rec`` argument contains the entry to be logged and is
an instance of the record type associated with the stream’s columns, and ``id``
identifies the log stream.

The logging framework defines one global hook policy hook: :zeek:see:`Log::log_stream_policy`.
For every log write, this hook gets invoked first. Any of its handlers may
decide to veto the log entry. The framework then iterates over the log stream's
filters. Each filter has a ``filter$policy`` hook of type :zeek:see:`Log::PolicyHook`.
Its handlers receive the log record, the ID of the log stream, and the filter
record itself. Each handler can veto the write. After the filter's hook has run,
any veto (by :zeek:see:`Log::log_stream_policy` or the filter's hook) aborts the
write via that filter. If no veto has occurred, the filter now steers the log
record to its output.

You can pass arbitrary state through these hook handlers. For example, you can
extending streams or filters via a :zeek:see:`redef`, or pass key-value pairs
via the ``filter$config`` table..

Since you'll often want to use uniform handling for all writes on a given
stream, log streams offer a default hook, provided when constructing the stream,
that the stream's filters will use if they don't provide their own. To support
hooks on your log streams, you should always define a default hook when creating
new streams, as follows:

.. code-block:: zeek

  module Foo;

  export {
      ## The logging stream identifier.
      redef enum Log::ID += { LOG };

      ## A default logging policy hook for the stream.
      global log_policy: Log::PolicyHook;

      # Define the record type that will contain the data to log.
      type Info: record {
          ts: time        &log;
          id: conn_id     &log;
          service: string &log &optional;
          missed_bytes: count &log &default=0;
      };
  }

  event zeek_init() &priority=5
      {
      # Create the stream, adding the default policy hook:
      Log::create_stream(Foo::LOG, [$columns=Info, $path="foo", $policy=log_policy]);
      }

With this hook in place, it’s now easy to add a filtering predicate for the ``Foo``
log from anywhere:

.. code-block:: zeek

  hook Foo::log_policy(rec: Foo::Info, id: Log::ID, filter: Log::Filter)
      {
      # Let's only log complete information:
      if ( rec$missed_bytes > 0 )
          break;
      }

The Zeek distribution features default hooks for all of its streams. Here’s a
more realistic example, using HTTP:

.. code-block:: zeek

  hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
      {
      # Record only connections with successfully analyzed HTTP traffic
      if ( ! rec?$service || rec$service != "http" )
          break;
      }

To override a hook selectively in a new filter, set the hook when adding the
filter to a stream:

.. code-block:: zeek

  hook my_policy(rec: Foo::Info, id: Log::ID, filter: Log::Filter)
      {
      # Let's only log incomplete flows:
      if ( rec$missed_bytes == 0 )
          break;
      }

  event zeek_init()
      {
      local filter: Log::Filter = [$name="incomplete-only",
                                   $path="foo-incomplete",
                                   $policy=my_policy];
      Log::add_filter(Foo::LOG, filter);
      }

Note that this approach has subtle implications: the new filter does not use the
``Foo::log_policy`` hook, and that hook does not get invoked for writes to this
filter. Any vetoes or additional processing implemented in ``Foo::log_policy``
handlers no longer happens for the new filter. Such hook replacement should
rarely be necessary; you may find it preferable to narrow the stream's default
handler to the filter in question:

.. code-block:: zeek

  hook Foo::log_policy(rec: Foo::Info, id: Log::ID, filter: Log::Filter)
      {
      if ( filter$name != "incomplete-only" )
          return;

      # Let's only log incomplete flows:
      if ( rec$missed_bytes == 0 )
          break;
      }

For tasks that need to run once per-write, not once per-write-and-filter,
use the :zeek:see:`Log::log_stream_policy` instead:

.. code-block:: zeek

  hook Log::log_stream_policy(rec: Foo::Info, id: Log::ID)
      {
      # Called once per write
      }

  hook Foo::log_policy(rec: Foo::Info, id: Log::ID, filter: Log::Filter)
      {
      # Called once for each of Foo's filters.
      }

To change an existing filter first retrieve it, then update it, and
re-establish it:

.. code-block:: zeek

  hook my_policy(rec: Foo::Info, id: Log::ID, filter: Log::Filter)
      {
      # Let's only log incomplete flows:
      if ( rec$missed_bytes == 0 )
          break;
      }

  event zeek_init()
      {
      local f = Log::get_filter(Foo::LOG, "default");
      f$policy = my_policy;
      Log::add_filter(Foo::LOG, f);
      }

.. note::

    Policy hooks can also modify the log records, but with subtle implications.
    The logging framework applies all of a stream’s log filters sequentially to
    the same log record, so modifications made in a hook handler will persist
    not only into subsequent handlers in the same hook, but also into any in
    filters processed subsequently. In contrast to hook priorities, filters
    provide no control over their processing order.

Log Rotation and Post-Processing
--------------------------------

The logging framework provides fine-grained control over when and how to rotate
log files. Log rotation means that Zeek periodically renames an active log
file, such as :file:`conn.log`, in a manner configurable by the user (e.g.,
renaming to :file:`conn_21-01-03_14-05-00.log` to timestamp it), and starts
over on a fresh :file:`conn.log` file. Post-processing means that Zeek can also
apply optional additional processing to the rotated file, such as compression
or file transfers. These mechanisms apply naturally to file-based log writers,
but are available to other writers as well for more generalized forms of
periodic additional processing of their outputs.

Rotation Timing
~~~~~~~~~~~~~~~

The log rotation interval is globally controllable for all filters by
redefining the :zeek:see:`Log::default_rotation_interval` constant, or
specifically for certain :zeek:see:`Log::Filter` instances by setting their
``interv`` field. The default value, ``0secs``, disables rotation.

.. note::

  When using ZeekControl, this option is set automatically via the ZeekControl
  configuration.

Here’s an example of changing just the :zeek:see:`Conn::LOG` stream’s default
filter rotation:

.. code-block:: zeek

  event zeek_init()
      {
      local f = Log::get_filter(Conn::LOG, "default");
      f$interv = 1 min;
      Log::add_filter(Conn::LOG, f);
      }

Controlling File Naming
~~~~~~~~~~~~~~~~~~~~~~~

The redef’able :zeek:see:`Log::rotation_format_func` determines the naming of
the rotated-to file. The logging framework invokes the function with sufficient
context (a :zeek:see:`Log::RotationFmtInfo` record), from which it determines
the output name in two parts: the output directory, and the output file’s base
name, meaning its name without a suffix. It returns these two components via a
:zeek:see:`Log::RotationPath` record. The output directory defaults to
:zeek:see:`Log::default_rotation_dir` (a config option) and incorporates a
timestamp in the base name, as specified by
:zeek:see:`Log::default_rotation_date_format`.

When :zeek:see:`Log::default_logdir` is in use and :zeek:see:`Log::rotation_format_func`
does not set an output directory (e.g. when :zeek:see:`Log::default_rotation_dir` is not set),
:zeek:see:`Log::default_logdir` is used as the default output directory.

For examples of customized log rotation, take a look at the
`relevant <https://github.com/zeek/zeek/blob/master/testing/btest/scripts/base/frameworks/logging/rotate-custom-fmt-func.zeek>`_
`test <https://github.com/zeek/zeek/blob/master/testing/btest/scripts/base/frameworks/logging/rotate-custom.zeek>`_
`cases <https://github.com/zeek/zeek/blob/master/testing/btest/scripts/base/frameworks/logging/rotate.zeek>`_.

Post-Processing of Rotated Logs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Post-processing can proceed via defaults configured across all log filters, or
with per-filter customizations. Zeek provides helpful default infrastructure to
simplify running shell commands on rotated logs, but you’re free to define your
own post-processing infrastructure from scratch.

By default, the :zeek:see:`Log::default_rotation_postprocessor_cmd`, if
defined, runs on every rotated log. The wrapper function making the actual
command invocation is :zeek:see:`Log::run_rotation_postprocessor_cmd`. It
passes six additional arguments to the configured shell command:

* The rotated-to file name (e.g. ``conn_21-01-03_14-05-00.log``)
* The original base name (e.g. ``conn``)
* The timestamp at which the original log file got created (e.g. ``21-01-03_14.04.00``)
* The timestamp at which the original log file got rotated (e.g. ``21-01-03_15.05.00``)
* ``1`` if Zeek is terminating, ``0`` otherwise
* The name of the writer (e.g. ``ascii`` for the ASCII writer)

.. warning::

   Zeek ignores failures (non-zero exit codes) of this shell command: the
   default rotation postprocessor command returns ``T`` regardless. Be careful
   if you implement your own postprocessor function: returning ``F`` from it
   will cause the corresponding log writer instance to shut down, therefore do
   so only when the writer really won’t be able to continue.

Zeek ships with ready-to-use postprocessors for file transfer via :doc:`SCP
</scripts/base/frameworks/logging/postprocessors/scp.zeek>` and
:doc:`SFTP </scripts/base/frameworks/logging/postprocessors/sftp.zeek>`.  The
Zeek project also provides an external tool, `zeek-archiver
<https://github.com/zeek/zeek-archiver>`_, that performs log compression
outside of the Zeek process for robustness.

Other Features
--------------

Log Extension Fields
~~~~~~~~~~~~~~~~~~~~

The logging framework provides rudimentary support for adding additional
columns to an already defined log format, globally for all logs or for
individual log filters only. Records returned by the
:zeek:see:`Log::default_ext_func` function get added to every log, and the
``ext_func`` member of :zeek:see:`Log::Filter` in filter records allows local
overrides.

You can configure a prefix string separately for either of these options — this
string ensures that the resulting fields don’t collide with already existing
log fields. The prefix defaults to an underscore, via
:zeek:see:`Log::default_ext_prefix`.  The ``ext_prefix`` field in filter
records overrides as needed.

The following example, taken straight from a Zeek testcase, adds three extra
columns to all logs:

.. code-block:: zeek

  type Extension: record {
      write_ts: time &log;
      stream: string &log;
      system_name: string &log;
  };

  function add_extension(path: string): Extension
    {
    return Extension($write_ts    = network_time(),
                     $stream      = path,
                     $system_name = peer_description);
    }

  redef Log::default_ext_func = add_extension;

A resulting :file:`conn.log`::

  #fields  _write_ts  _stream  _system_name  ts  uid …
  #types  time  string  string  time  string  …
  1071580905.346457  conn  zeek  1071580904.891921  Cod6Wj3YeJFHgkaO8j …

.. note::

   Extension fields remain separate from the original log record. They remain
   invisible to filters, policy hooks, and log events. *After* filter processing
   determines that an entry is to be logged, the framework simply tucks the
   extension's members onto the list of fields to write out.

Field Name Mapping
~~~~~~~~~~~~~~~~~~

On occasion it can be handy to rewrite column names as they appear in a Zeek
log. A typical use case for this would be to ensure that column naming complies
with the requirements of your log ingestion system. To achieve this, you can
provide name translation maps, and here too you can do this either globally or
per-filter. The maps are simple string tables with the keys being Zeek’s field
names and the values being the ones to actually write out. Field names not
present in the maps remain unchanged. The global variant is the (normally
empty) :zeek:see:`Log::default_field_name_map`, and the corresponding
filter-local equivalent is the filter’s ``field_name_map`` member.

For example, the following name map gets rid of the dots in the usual naming of
connection IDs:

.. code-block:: zeek

  redef Log::default_field_name_map = {
       ["id.orig_h"] = "id_orig_h",
       ["id.orig_p"] = "id_orig_p",
       ["id.resp_h"] = "id_resp_h",
       ["id.resp_p"] = "id_resp_p"
  };

With it, all logs rendering a connection identifier tuple now use ...

::

  #fields  ts  uid  id_orig_h  id_orig_p  id_resp_h  id_resp_p ...

… instead of the default names:

::

  #fields  ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p ...

If you’d prefer this change only for a given log filter, make the change to the
filter record directly. The following changes the naming only for
:file:`conn.log`:

.. code-block:: zeek

  event zeek_init()
     {
     local f = Log::get_filter(Conn::LOG, "default");
     f$field_name_map = table(
         ["id.orig_h"] = "id_orig_h",
         ["id.orig_p"] = "id_orig_p",
         ["id.resp_h"] = "id_resp_h",
         ["id.resp_p"] = "id_resp_p");
     Log::add_filter(Conn::LOG, f);
     }

Printing to Log Messages
~~~~~~~~~~~~~~~~~~~~~~~~

Zeek’s :zeek:see:`print` statement normally writes to ``stdout`` or a specific
output file. By adjusting the :zeek:see:`Log::print_to_log` enum value you can
redirect such statements to instead go directly into a Zeek log. Possible
values include:

* :zeek:see:`Log::REDIRECT_NONE`: the default, which doesn’t involve Zeek logs
* :zeek:see:`Log::REDIRECT_STDOUT`: prints that would normally go to stdout go
  to a log
* :zeek:see:`Log::REDIRECT_ALL`: any prints end up in a log instead of stdout
  or other files

The :zeek:see:`Log::print_log_path` defines the name of the log file,
:zeek:see:`Log::PrintLogInfo` its columns, and :zeek:see:`Log::log_print`
events allow you to process logged messages via event handlers.

Local vs Remote Logging
~~~~~~~~~~~~~~~~~~~~~~~

In its log processing, Zeek considers whether log writes should happen locally
to a Zeek node or remotely on another node, after forwarding log entries to it.
Single-node Zeek setups default to local logging, whereas cluster setups enable
local logging only on logger nodes, and log remotely on all but the logger
nodes. You normally don’t need to go near these settings, but you can do so by
``redef``’ing the :zeek:see:`Log::enable_local_logging` and
:zeek:see:`Log::enable_remote_logging` booleans, respectively.

Writers
=======

Each filter has a writer. If you do not specify a writer when adding a filter
to a stream, then the ASCII writer is the default.

There are two ways to specify a non-default writer. To change the default
writer for all log filters, just redefine the :zeek:see:`Log::default_writer`
option.  Alternatively, you can specify the writer to use on a per-filter basis
by setting a value for the filter’s ``writer`` field. Consult the documentation
of the writer to use to see if there are other options that are needed.

ASCII Writer
------------

By default, the ASCII writer outputs log files that begin with several lines of
metadata, followed by the actual log output. The metadata describes the format
of the log file, the ``path`` of the log (i.e., the log filename without file
extension), and also specifies the time that the log was created and the time
when Zeek finished writing to it. The ASCII writer has a number of options for
customizing the format of its output, see
:doc:`/scripts/base/frameworks/logging/writers/ascii.zeek`. If you change the
output format options, then be careful to check whether your post-processing
scripts can still recognize your log files.

Some writer options are global (i.e., they affect all log filters using that
log writer). For example, to change the output format of all ASCII logs to JSON
format:

.. code-block:: zeek

  redef LogAscii::use_json = T;


Some writer options are filter-specific (i.e., they affect only the filters
that explicitly specify the option). For example, to change the output format
of the :file:`conn.log` only:

.. code-block:: zeek

  event zeek_init()
      {
      local f = Log::get_filter(Conn::LOG, "default");
      # Use tab-separated-value mode
      f$config = table(["tsv"] = "T");
      Log::add_filter(Conn::LOG, f);
      }

.. _logging-sqlite-writer:

SQLite Writer
-------------

SQLite is a simple, file-based, widely used SQL database system. Using SQLite
allows Zeek to write and access data in a format that is easy to use in
interchange with other applications. Due to the transactional nature of SQLite,
databases can be used by several applications simultaneously. Zeek’s input
framework supports a :ref:`SQLite reader <input-sqlite-reader>`.

Logging support for SQLite is available in all Zeek installations. There is no
need to load any additional scripts or for any compile-time configurations.
Sending data from existing logging streams to SQLite is rather straightforward.
Most likely you’ll want SQLite output only for select log filters, so you have
to configure one to use the SQLite writer. The following example code adds
SQLite as a filter for the connection log:

.. code-block:: zeek

  event zeek_init()
      {
      local filter: Log::Filter =
          [
          $name="sqlite",
          $path="/var/db/conn",
          $config=table(["tablename"] = "conn"),
          $writer=Log::WRITER_SQLITE
          ];

       Log::add_filter(Conn::LOG, filter);
      }

Zeek will create the database file :file:`/var/db/conn.sqlite` if it does not
already exist. It will also create a table with the name ``conn`` (if it does
not exist) and start appending connection information to the table.

Zeek does not currently support rotating SQLite databases as it does for ASCII
logs. You have to take care to create them in adequate locations.

If you examine the resulting SQLite database, the schema will contain the same
fields that are present in the ASCII log files:

.. code-block:: console

  sqlite3 /var/db/conn.sqlite

::

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

Note that with the above code the ASCII :file:`conn.log` will still be created,
because it adds an additional log filter alongside the default, ASCII-logging
one. To prevent this you can remove the default filter:

.. code-block:: zeek

  Log::remove_filter(Conn::LOG, "default");

To create a custom SQLite log file, you have to create a new log stream that
contains just the information you want to commit to the database. See the above
documentation on how to create custom log streams.

None Writer
-----------

The ``None`` writer, selected via :zeek:see:`Log::WRITER_NONE`, is largely a
troubleshooting and development aide. It discards all log entries it receives,
but behaves like a proper writer to the rest of the logging framework,
including, for example, pretended log rotation. If you enable its debugging
mode by setting :zeek:see:`LogNone::debug` to ``T``, Zeek reports operational
details about the writer’s activity to ``stdout``.
