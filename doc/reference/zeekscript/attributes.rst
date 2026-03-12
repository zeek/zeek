.. _attributes:
 
Attributes
==========

The Zeek scripting language supports customization of many language elements via
*attributes*. For example, attributes can ensure that a function gets invoked
whenever you modify a table, automatically expire elements from a set, or tell
the :ref:`logging framework <framework-logging>` which record fields you'd like
it to write. Zeek features the following attributes:

.. list-table::
  :header-rows: 1

  * - Name
    - Description

  * - :zeek:attr:`&redef`
    - Redefine a global constant or extend a type.

  * - :zeek:attr:`&priority`
    - Specify priority for event handler or hook.

  * - :zeek:attr:`&log`
    - Mark a record field as to be written to a log.

  * - :zeek:attr:`&optional`
    - Allow a record field value to be missing.

  * - :zeek:attr:`&default`
    - Specify a default value.

  * - :zeek:attr:`&default_insert`
    - Specify a default value for tables with insert behavior.

  * - :zeek:attr:`&add_func`
    - Specify a function to call for each ``redef +=``.

  * - :zeek:attr:`&delete_func`
    - Same as ``&add_func``, except for ``redef -=``.

  * - :zeek:attr:`&expire_func`
    - Specify a function to call when container element expires.

  * - :zeek:attr:`&read_expire`
    - Specify a read timeout interval.

  * - :zeek:attr:`&write_expire`
    - Specify a write timeout interval.

  * - :zeek:attr:`&create_expire`
    - Specify a creation timeout interval.

  * - :zeek:attr:`&on_change`
    - Specify a function to call on set/table changes

  * - :zeek:attr:`&publish_on_change`
    - Enable publishing set/table changes to a configurable topic.

  * - :zeek:attr:`&raw_output`
    - Open file in raw mode (chars. are not escaped).

  * - :zeek:attr:`&error_handler`
    - Used internally for reporter framework events.

  * - :zeek:attr:`&type_column`
    - Used by input framework for :zeek:type:`port` type.

  * - :zeek:attr:`&backend`
    - Used for table persistence/synchronization.

  * - :zeek:attr:`&broker_store`
    - Used for table persistence/synchronization.

  * - :zeek:attr:`&broker_allow_complex_type`
    - Used for table persistence/synchronization.

  * - :zeek:attr:`&ordered`
    - Used for predictable member iteration of tables and sets.

  * - :zeek:attr:`&deprecated`
    - Marks an identifier as deprecated.

  * - :zeek:attr:`&is_assigned`
    - Suppress "used before defined" warnings from ``zeek -u`` analysis.

  * - :zeek:attr:`&is_used`
    - Suppress lack-of-use warnings from ``zeek -u`` analysis.

  * - :zeek:attr:`&group`
    - Annotates event handlers and hooks with event groups.

.. _attribute-propagation-pitfalls:

.. warning::

    A confusing pitfall can be mistaking that attributes bind to a *variable*
    or a *type*, where in reality they bind to a *value*.  Example:

    .. code-block:: zeek

        global my_table: table[count] of string &create_expire=1sec;

        event zeek_init()
            {
            my_table = table();
            my_table[1] = "foo";
            }

    In the above, the re-assignment of ``my_table`` will also drop the original
    *value*'s :zeek:attr:`&create_expire` and no entries will ever be expired
    from ``my_table``.  The alternate way of re-assignment that creates a new
    table *value* with the expected attribute would be:

    .. code-block:: zeek

        my_table = table() &create_expire=1sec;

Here is a more detailed explanation of each attribute:

.. zeek:attr:: &redef

&redef
------

Allows use of a :zeek:keyword:`redef` to redefine initial values of
global variables (i.e., variables declared either :zeek:keyword:`global`
or :zeek:keyword:`const`).  Example:

.. code-block:: zeek

    const clever = T &redef;
    global cache_size = 256 &redef;

Note that a variable declared ``global`` can also have its value changed
with assignment statements (doesn't matter if it has the :zeek:attr:`&redef`
attribute or not).

.. zeek:attr:: &priority

&priority
---------

Specifies the execution priority (as a signed integer) of a hook or
event handler. Higher values are executed before lower ones. The
default value is ``0``.  Example:

.. code-block:: zeek

    event zeek_init() &priority=10
        {
        print "high priority";
        }

.. zeek:attr:: &log

&log
----

When a :zeek:type:`record` field has the ``&log`` attribute, this field is
included as a column in the log stream associated with the record type. This
association happens with :zeek:see:`Log::create_stream` and commonly looks as
follows:

.. code-block:: zeek

    redef enum Log::ID += { LOG };

    type Info: record {
        ts: time &log &default=network_time();
        id: conn_id &log;
        msg: string &log;
        hidden: count &default=0;  # This is not logged.
    };

    event zeek_init() {
        Log::create_stream(LOG, [$columns=Info, $path="example"]);
    }

The log stream above will have the columns ``ts``, ``id`` and ``msg``.

When ``&log`` is placed at the end of a record type declaration, all fields
listed in the declaration will have the ``&log`` attribute implicitly.

.. code-block:: zeek

    type conn_id: record {
        orig_h: addr;
        orig_p: port;
        resp_h: addr;
        resp_p: port;
    } &log;

Fields added to such a record types later on using :zeek:see:`redef` need to
explicitly specify ``&log`` again, however.

.. zeek:attr:: &optional

&optional
---------

Allows a record field value to be missing. Zeek allows such fields to remain
uninitialized and unassigned, and to have assigned values removed via
:zeek:keyword:`delete`.

In this example, the record could be instantiated with either
``myrec($a=127.0.0.1)`` or ``myrec($a=127.0.0.1, $b=80/tcp)``:

.. code-block:: zeek

    type myrec: record { a: addr; b: port &optional; };

The ``?$`` operator can be used to check if a record field has a value or
not (it returns a ``bool`` value of ``T`` if the field has a value,
and ``F`` if not).

.. zeek:attr:: &default

&default
--------

Specifies a default value for a record field, container element, or a
function/hook/event parameter.

In this example, the record could be instantiated with either
``myrec($a=5, $c=3.14)`` or ``myrec($a=5, $b=53/udp, $c=3.14)``:

.. code-block:: zeek

    type myrec: record { a: count; b: port &default=80/tcp; c: double; };

In this example, the table will return the string ``"foo"`` for any
attempted access to a non-existing index:

.. code-block:: zeek

    global mytable: table[count] of string &default="foo";

In addition to constant values as shown above, the :zeek:attr:`&default` attribute
also accepts arbitrary Zeek expressions. For example, arithmetic expressions and
function calls are possible:

.. code-block:: zeek

   type Info: record {
       ts: time &log &default=network_time();
       ts_ms: double &log &default=time_to_double(network_time()) * 1000;
   };

The expressions are evaluated whenever a new record is instantiated.

On tables, the :zeek:attr:`&default` attribute can further be set to a function
(including an anonymous lambda function), which will be invoked for any read access
to a non-existing index to generate a substitute result. The signature of such a default function
has to match with the index and value types of the given table. Below, a default
function for a table with a composite index and value type of :zeek:type:`string` is shown.
The arguments for the function call, ``c`` and ``s`` below, are populated with
the values used for the index:

.. code-block:: zeek

    function table_default(c: count, s: string): string {
        return fmt("unknown-%s-%s", c, s);
    }

    global mytable: table[count, string] of string &default=table_default;

    print mytable[0, "a"];

Using an anonymous function instead looks as follows:

.. code-block:: zeek

    global mytable: table[count, string] of string &default=function(c: count, s: string): string {
        return fmt("unknown-%s-%s", c, s);
    };

    print mytable[0, "a"];

The output of both these examples is ``unknown-0-a``.

A common usage pattern of the :zeek:attr:`&default` attribute in Zeek's base
scripts is to format a default textual representation for unknown protocol
values that are otherwise mapped to textual descriptions.
The following excerpt is from :doc:`/scripts/base/protocols/dns/consts.zeek`
mapping numeric DNS query types to their textual representation. A default
function is used to produce a string containing the numeric value of query types:

.. code-block:: zeek

    ## Mapping of DNS query type codes to human readable string
    ## representation.
    const query_types = {
        [1] = "A",
        [2] = "NS",
        [3] = "MD",
        [4] = "MF",
        [5] = "CNAME",
        # many many more ...
        [65422] = "XPF",
        [65521] = "INTEGRITY",
    } &default = function(n: count): string { return fmt("query-%d", n); };


Note that when accessing a non-existing index, the created default value will
not be inserted into the table. The following script will output ``foo``,
but the table remains empty. The second print statement outputs ``0``:

.. code-block:: zeek

    global mytable: table[count] of string &default="foo";
    print mytable[0];
    print |mytable|;

For inserting the created default value into a table, the :zeek:attr:`&default_insert`
attribute can be used instead.

When used with function/hook/event parameters, all of the parameters
with the :zeek:attr:`&default` attribute must come after all other parameters.
For example, the following function could be called either as ``myfunc(5)``
or as ``myfunc(5, 53/udp)``:

.. code-block:: zeek

    function myfunc(a: count, b: port &default=80/tcp)
        {
        print a, b;
        }

.. zeek:attr:: &default_insert

&default_insert
---------------

.. versionadded:: 6.1

This attribute is only applicable to tables. :zeek:attr:`&default_insert`
provides the same functionality as table's :zeek:attr:`&default` but with the addition
that upon access to a non-existing index, the created value will be inserted
into the table. For complex value types like tables or record types used for
tracking further state, :zeek:attr:`&default_insert` is often more useful and
efficient than :zeek:attr:`&default`.

.. zeek:attr:: &add_func

&add_func
---------

Can be applied to an identifier with &redef to specify a function to
be called any time a ``redef <id> += ...`` declaration is parsed.  The
function takes two arguments of the same type as the identifier, the first
being the old value of the variable and the second being the new
value given after the ``+=`` operator in the :zeek:keyword:`redef` declaration.  The
return value of the function will be the actual new value of the
variable after the "redef" declaration is parsed.

.. zeek:attr:: &delete_func

&delete_func
------------

Same as :zeek:attr:`&add_func`, except for :zeek:keyword:`redef` declarations
that use the ``-=`` operator.

.. zeek:attr:: &expire_func

&expire_func
------------

Called right before a container element expires. The function's first
argument is of the same type as the container it is associated with.
The function then takes a variable number of arguments equal to the
number of indexes in the container. For example, for a
``table[string,string] of count`` the expire function signature is:

.. code-block:: zeek

    function(t: table[string, string] of count, s: string, s2: string): interval

The return value is an :zeek:type:`interval` indicating the amount of
additional time to wait before expiring the container element at the
given index (which will trigger another execution of this function).

.. zeek:attr:: &read_expire

&read_expire
------------

Specifies a read expiration timeout for container elements. That is,
the element expires after the given amount of time since the last
time it has been read. Note that a write also counts as a read.

.. zeek:attr:: &write_expire

&write_expire
-------------

Specifies a write expiration timeout for container elements. That
is, the element expires after the given amount of time since the
last time it has been written.

.. zeek:attr:: &create_expire

&create_expire
--------------

Specifies a creation expiration timeout for container elements. That
is, the element expires after the given amount of time since it has
been inserted into the container, regardless of any reads or writes.

.. note::

   In order to support expiration timeouts, Zeek associates a timer
   with each container that weeds out stale entries. For containers with many members,
   Zeek needs to keep an eye on the amount of effort spent expiring
   elements. It does this via three configurable properties:

   * :zeek:see:`table_expire_interval` specifies how frequently Zeek checks a
     container's members. The interval establishes an upper bound on how long it
     may take Zeek to react to an element's expiration.

   * :zeek:see:`table_incremental_step` specifies how many members Zeek
     checks in one batch.

   * :zeek:see:`table_expire_delay` interval specifies how long Zeek
     waits until it processes the next batch of members.

.. zeek:attr:: &on_change

&on_change
----------

Called right after a change has been applied to a container. The function's
first argument is of the same type as the container it is associated with,
followed by a :zeek:see:`TableChange` record which specifies the type of change
that happened. The function then takes a variable number of arguments equal to
the number of indexes in the container, followed by an argument for the value
of the container (if the container has a value) For example, for a
``table[string,string] of count`` the ``&on_change`` function signature is:

.. code-block:: zeek

    function(t: table[string, string] of count, tpe: TableChange,
             s: string, s2: string, val: count)

For a ``set[count]`` the function signature is:

.. code-block:: zeek

    function(s: set[count], tpe: TableChange, c: count)

The passed value specifies the state of a value before the change, where this
makes sense. In case a element is changed, removed, or expired, the passed
value will be the value before the change, removal, or expiration. When an
element is added, the passed value will be the value of the added element
(since no old element existed).

Note that the ``&on_change`` function is only called when the container itself
is modified (due to an assignment, delete operation, or expiry). When a
container contains a complex element (like a record, set, or vector), changes
to these complex elements are not propagated back to the parent.  For example,
in this example the ``change_function`` for the table will only be called once,
when ``s`` is inserted,  but it will not be called when ``s`` is changed:

.. code-block:: zeek

    local t: table[string] of set[string] &on_change=change_function;
    local s: set[string] = set();
    t["s"] = s; # change_function of t is called
    add s["a"]; # change_function of t is _not_ called.

Also note that the ``&on_change`` function of a container will not be called
when the container is already executing its ``&on_change`` function. Thus,
writing an ``&on_change`` function like this is supported and will not lead to
a infinite loop:

.. code-block:: zeek

    local t: table[string] of set[string] &on_change=change_function;

    function change_function(t: table[string, int] of count, tpe: TableChange,
                             idxa: string, idxb: int, val: count)
        {
        t[idxa, idxb] = val+1;
        }

.. zeek:attr:: &publish_on_change

&publish_on_change
------------------

.. versionadded:: 8.2

The ``&publish_on_change`` attribute enables automatically publishing changes to
global :zeek:type:`table` or :zeek:type:`set` variables to a configurable topic.
In Zeek, sets are essentially tables with nil values, so we use the terms interchangeably
in the following description.
This attribute provides an alternative state distribution primitive that works
with any cluster backend, replacing the older and Broker-specific :zeek:attr:`&backend`
and :zeek:attr:`&broker_store` attributes.

You assign the ``&publish_on_change`` attribute an instance of a :zeek:see:`Cluster::PublishOnChangeAttr`
record in ``[ ...field assignments... ]`` style to configure the publish behavior
for a given table.
Minimally, you'll need to provide a non-empty :zeek:field:`Cluster::PublishOnChangeAttr$changes`
field to select which type of changes Zeek will publish. The :zeek:field:`changes` field
takes a :zeek:type:`set` of :zeek:type:`TableChange` values.

.. code-block:: zeek

    module Test;

    global endpoints: table[addr, addr] of string &write_expire=30sec &publish_on_change=[
        $changes=set(TABLE_ELEMENT_NEW),
    ];

This attribute is a good fit if you need to implement a cluster-wide suppressions table or
best-effort state distribution mechanism via Zeek's :zeek:type:`table` and
:zeek:type:`set` types.
If you need stronger consistency and persistence guarantees, look into using the
:ref:`Storage Framework <framework-storage>` instead.

You should not think of this attribute as a synchronization primitive for tables.
Instead, it's a mechanism to produce an event stream of table changes. Zeek nodes
receiving the event stream in turn apply the changes to their own local instance
of the table via the default :zeek:see:`Cluster::table_change_infos` handler.

The ``&publish_on_change`` attribute's behavior is closely related to the
:zeek:attr:`&on_change` attribute. However, the ``&publish_on_change`` attribute
only works on global tables and sets. It is not possible to use ``&publish_on_change`` on
local variables or on tables that are part of records. Similar to ``&on_change``,
modifications to aggregate or container values are not recognized as table changes
and therefore never published.

The observable cluster-wide behavior depends heavily on which nodes in a Zeek cluster
modify which keys, the type of changes selected for publishing via the
:zeek:field:`changes` field, and messaging delays in the Zeek cluster.
There's also no automatic restore mechanism when using the ``&publish_on_change``
attribute. When a Zeek node crashes and restarts, its local table will be empty.
See the paragraph about :zeek:see:`Cluster::publish_table` at the end of this section.
Additionally, as table changes are published as remote Zeek events, when a Zeek cluster
backend becomes overloaded, sending and receiving Zeek nodes may drop table changes
arbitrarily.

In summary, it's best to stick with usages of ``&publish_on_change`` that are easy
to explain. For example, sending only new entries in a table to other Zeek nodes and
using :zeek:attr:`&write_expire` for cleanup of stale entries makes it easy to implement
a well-understood cluster-wide caching table.
On the other hand, publishing :zeek:see:`TABLE_ELEMENT_NEW`, :zeek:see:`TABLE_ELEMENT_REMOVED`
and :zeek:see:`TABLE_ELEMENT_CHANGED` together becomes difficult to reason about
when the same key is modified by different Zeek nodes, but might be reasonable if
every key has exactly one owner node.

By default, the topic used for publishing changes is ``zeek/table/<identifier>/``.
In the example above, the topic is ``zeek/table/Test::endpoints/``.
Alternatively, the topic can be customized by setting the :zeek:field:`Cluster::PublishOnChangeAttr$topic`
field of the ``&publish_on_change`` record.
For example, to publish changes only to other Zeek worker nodes, excluding manager,
proxy and logger nodes, set :zeek:field:`Cluster::PublishOnChangeAttr$topic` to :zeek:see:`Cluster::worker_topic`:

.. code-block:: zeek

    global endpoints: table[addr, addr] of string &write_expire=30sec &publish_on_change=[
        $changes=set(TABLE_ELEMENT_NEW),
        $topic=Cluster::worker_topic,
    ];

Additionally, it's possible to set :zeek:field:`Cluster::PublishOnChangeAttr$topic`
to a function returning a :zeek:type:`string` that's called on every change. The
return value of this function will be used as the topic for publishing. The function's
parameters need to match the table index types.
For instance, using :zeek:see:`Cluster::hrw_topic`, inserts done by worker nodes
can be sharded across available proxy nodes based on the originator address:

.. code-block:: zeek

    global endpoints: table[addr, addr] of string &write_expire=30sec &publish_on_change=[
        $changes=set(TABLE_ELEMENT_NEW),
        # Compute a per-element topic from the proxy pool using the originator address.
        $topic=function(orig_h: addr, resp_h: addr): string {
            return Cluster::hrw_topic(Cluster::proxy_pool, cat(orig_h));
        },
    ];

    event new_connection(c: connection)
        {
        endpoints[c$id$orig_h, c$id$resp_h] = c$uid;
        }

.. note::

   Due to limitations in Broker's publish/subscribe visibility, worker nodes
   forward their table changes to the central manager node which in turn publishes
   the changes to the intended topic. This results in extra overhead on the manager
   when the Broker cluster backend is in use. Using ZeroMQ does not incur this extra
   overhead as remote events from one worker are visible to all other workers in a
   cluster, avoiding the need to route these events through the manager.


The :zeek:field:`Cluster::PublishOnChangeAttr$max_batch_delay` and
:zeek:field:`Cluster::PublishOnChangeAttr$max_batch_size` fields of the ``&publish_on_change``
record have non-zero defaults. That is, batching is enabled by default. The main motivation
is that it's more efficient to coalesce multiple table changes into a single event,
rather than sending a single event per change. This comes at the expense of increased
latency and staleness. To immediately publish any changes to a table, set one or both
of these fields explicitly to a zero value:

.. code-block:: zeek

    module Test;

    global endpoints: table[addr, addr] of string &write_expire=30sec &publish_on_change=[
        $changes=set(TABLE_ELEMENT_NEW),
        $max_batch_delay=0sec,
        $max_batch_size=0,
    ];

Note however that even with a ``0sec`` delay, the asynchronous nature of remote
event publishing in a Zeek cluster means there can still be races. It's just that
the internal ``&publish_on_change`` logic does not batch/queue changes anymore.

Internally, Zeek records every change as a :zeek:see:`Cluster::TableChangeInfo`
value and batches/queues these for a per-table configurable interval
or until the maximum number of changes is batched/queued.
All batched changes are published using, conceptually, a single :zeek:see:`Cluster::publish`
invocation of a :zeek:see:`Cluster::table_change_infos` event with two parameters.
The first parameter is a header of type :zeek:see:`Cluster::TableChangeHeader` with common information.
The second parameter is a :zeek:see:`Cluster::TableChangeInfos` vector.

.. code-block:: zeek

   event Cluster::table_change_infos(tcheader: Cluster::TableChangeHeader, tcinfos: Cluster::TableChangeInfos);


The :zeek:see:`Cluster::apply_table_change_infos_policy` hook exists
to intercept, change or simply debug incoming :zeek:see:`Cluster::TableChangeInfo` records.
Breaking from this hook skips applying the changes. This is meant for fairly advanced
and low-level use-cases and should normally not be needed. If you want to experiment
with other strategies to apply changes to tables or replicate the event stream to an
external system, this might be the hook you're looking for, though.

If you intend to distribute the current content of a table to another node that
just restarted, you may use the :zeek:see:`Cluster::publish_table` helper. This
function will send the contents of a table with a ``&publish_on_change`` attribute
to the provided topic in the form of multiple :zeek:see:`Cluster::table_change_infos`
events containing all of the table's contents.


.. code-block:: zeek

    global endpoints: table[addr, addr] of string &write_expire=300sec &publish_on_change=[
        $changes=set(TABLE_ELEMENT_NEW),
    ];

    event Cluster::node_up(name: string, id: string)
        {
        # The manager node pushes the full endpoints table to a re-starting node.
        if ( Cluster::local_node_type() == Cluster::MANAGER )
            Cluster::publish_table(Cluster::node_topic(name), endpoints);
        }

.. warning::

    If your table has hundreds of thousands of entries, using :zeek:see:`Cluster::publish_table`
    may introduce non-negligible cluster overhead.

.. note::

    As of Zeek 8.2, :zeek:see:`Cluster::publish_table` does not convey expiration
    times of table entries. That is, the receiving node computes expiration times
    anew based on its network time when it processes the changes. We may include
    expiration time in the :zeek:see:`Cluster::TableChangeInfo` record in the future,
    but as of now there are APIs missing on the ``TableVal`` class to enable this.


.. zeek:attr:: &raw_output

&raw_output
-----------

Opens a file in raw mode, i.e., non-ASCII characters are not escaped.

.. zeek:attr:: &error_handler

&error_handler
--------------

Internally set on the events that are associated with the reporter
framework: :zeek:id:`reporter_info`, :zeek:id:`reporter_warning`, and
:zeek:id:`reporter_error`.  It prevents any handlers of those events
from being able to generate reporter messages that go through any of
those events (i.e., it prevents an infinite event recursion).  Instead,
such nested reporter messages are output to stderr.

.. zeek:attr:: &type_column

&type_column
------------

Used by the input framework. It can be used on columns of type
:zeek:type:`port` (such a column only contains the port number) and
specifies the name of an additional column in
the input file which specifies the protocol of the port (tcp/udp/icmp).

In the following example, the input file would contain four columns
named ``ip``, ``srcp``, ``proto``, and ``msg``:

.. code-block:: zeek

    type Idx: record {
        ip: addr;
    };


    type Val: record {
        srcp: port &type_column = "proto";
        msg: string;
    };

.. zeek:attr:: &backend

&backend
--------

.. deprecated:: 8.1 This attribute is Broker specific, use :zeek:attr:`&publish_on_change` or the :ref:`Storage Framework <framework-storage>` instead.

Used for persisting tables/sets and/or synchronizing them over a cluster.

This attribute binds a table to a Broker store. Changes to the table
are sent to the Broker store, and changes to the Broker store are applied
back to the table.

Since Broker stores are synchronized over a cluster, this sends
table changes to all other nodes in the cluster. When using a persistent Broker
store backend, the content of the tables/sets will be restored on startup.

This attribute expects the type of backend you want to use for the table. For
example, to bind a table to a memory-backed Broker store, use:

.. code-block:: zeek

    global t: table[string] of count &backend=Broker::MEMORY;

.. zeek:attr:: &broker_store

&broker_store
-------------

.. deprecated:: 8.1 This attribute is Broker specific, use :zeek:attr:`&publish_on_change` or the :ref:`Storage Framework <framework-storage>` instead.

This attribute is similar to :zeek:attr:`&backend` in allowing a Zeek table to
bind to a Broker store. It differs from :zeek:attr:`&backend` as this attribute
allows you to specify the Broker store you want to bind, without creating it.

Use this if you want to bind a table to a Broker store with special options.

Example:

.. code-block:: zeek

     global teststore: opaque of Broker::Store;

     global t: table[string] of count &broker_store="teststore";

     event zeek_init()
         {
         teststore = Broker::create_master("teststore");
         }

.. zeek:attr:: &broker_allow_complex_type

&broker_allow_complex_type
--------------------------

By default only tables containing atomic types can be bound to Broker stores.
Specifying this attribute before :zeek:attr:`&backend` or :zeek:attr:`&broker_store`
disables this safety feature and allows complex types to be stored in a Broker backed
table.

.. warning::

    Storing complex types in Broker backed store comes with severe restrictions.
    When you modify a stored complex type after inserting it into a table, that change in a stored complex type
    will *not propagate* to Broker. Hence to send out the new value, so that it will be persisted/synchronized
    over the cluster, you will have to re-insert the complex type into the local zeek table.

    For example:

    .. code-block:: zeek

            type testrec: record {
                a: count;
            };

            global t: table[string] of testrec &broker_allow_complex_type &backend=Broker::MEMORY;

            event zeek_init()
                {
                local rec = testrec($a=5);
                t["test"] = rec;
                rec$a = 6; # This will not propagate to Broker! You have to re-insert.
                # Propagate new value to Broker:
                t["test"] = rec;
                }

.. zeek:attr:: &ordered

&ordered
--------

Used on tables and sets, this attribute ensures that iteration yields members in
the order they were inserted. Without this attribute, the iteration order remains
undefined. The following is guaranteed to print "foo", "bar", and "baz", in that
order:

.. code-block:: zeek

    global sset: set[string] &ordered;

    event zeek_init()
        {
        add sset["foo"];
        add sset["bar"];
        add sset["baz"];

        for ( s in sset )
            print s;
        }

.. zeek:attr:: &deprecated

&deprecated
-----------

The associated identifier is marked as deprecated and will be
removed in a future version of Zeek.  Look in the :file:`NEWS` file for more
instructions to migrate code that uses deprecated functionality.
This attribute can be assigned an optional string literal value to
print along with the deprecation warning. The preferred format of
this warning message should include the version number in which
the identifier will be removed:

.. code-block:: zeek

    type warned: string &deprecated="Remove in vX.Y.  This type is deprecated because of reasons, use 'foo' instead.";

.. zeek:attr:: &is_assigned

&is_assigned
------------

Zeek has static analysis capabilities
for detecting locations in a script that attempt to use a
local variable before it is necessarily defined/assigned.  You activate
this using the ``-u`` command-line flag.

However the static analysis lacks sufficient power to tell that some
values are being used safely (guaranteed to have been assigned).  In order to
enable users to employ ``-u`` on their own scripts without being
distracted by these false positives, the ``&is_assigned`` attribute can be
associated with a variable to inform Zeek's analysis that the
script writer asserts the value will be set, suppressing the associated
warnings.

.. code-block:: zeek
  :caption: test1.zeek
  :linenos:

    event zeek_init()
        {
        local a: count;
        print a;
        }

.. code-block:: console

  $ zeek -b -u test1.zeek

::

  warning in ./test1.zeek, line 4: possibly used without definition (a)
  expression error in ./test1.zeek, line 4: value used but not set (a)

.. code-block:: zeek
  :caption: test2.zeek
  :linenos:

    event zeek_init()
        {
        # Note this is not a real place to want to use &is_assigned since it's
        # clearly a bug, but it demonstrates suppression of warning.
        local a: count &is_assigned;
        print a;
        }

.. code-block:: console

  $ zeek -b -u test2.zeek

::

  expression error in ./test2.zeek, line 6: value used but not set (a)

.. zeek:attr:: &is_used

&is_used
--------

Zeek has static analysis capabilities for detecting locations in a script where
local variables are assigned values that are not subsequently used (i.e. "dead
code").

It can also warn about unused functions, hooks, and event handlers.  The intent
behind these checks is to catch instances where the script writer has introduced
typos in names, or has forgotten to remove code that's no longer needed.  For
functions and hooks, "unused" means the function/hook is neither exported nor in the
global scope, and no "live" (i.e., not "unused") function/hook/event handler
calls it.  For event handlers, "unused" means that the event engine does not
generate the event, nor do any "live" functions/hooks/event handlers generate it.

Zeek never reports any functions/hooks/event handlers that are marked deprecated
(via :zeek:attr:`&deprecated`) as unused.

For cases where it's desirable to suppress the warning, the
``&is_used`` attribute may be applied, for example:

.. code-block:: zeek
  :caption: test.zeek
  :linenos:

    module Test;

    export {
        global baz: function();
    }

    function foo()
        {
        }

    function bar() &is_used
        {
        }

    function baz()
        {
        }

    event zeek_init()
        {
        local please_warn: string = "test";
        local please_no_warning: string = "test" &is_used;
        }

.. code-block:: console

  $ zeek -a -b -u test.zeek

::

  warning in ./test.zeek, line 7: non-exported function does not have any callers (Test::foo)
  warning: Test::please_warn assignment unused: Test::please_warn = test; ./test.zeek, line 21

.. zeek:attr:: &group

&group
------

The ``&group`` attribute can be used on event handlers and hooks to add them
into event groups.
By default, all event groups are enabled. Disabling an event group disables
all event handlers and hooks with a matching ``&group`` attribute. When an
event handler or hook is part of multiple groups it is enabled only if all
groups are enabled.

.. code-block:: zeek

     event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) &group="my-http-group"
         {
         ...
         }

     event zeek_init()
         {
         disable_event_group("my-http-group");
         }

See also the documentation for the functions :zeek:see:`enable_event_group`
and :zeek:see:`disable_event_group`.
