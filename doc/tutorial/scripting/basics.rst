.. _basics_video: https://youtu.be/nae8cdrUUKY?si=aGXnYaHPYjkcZk_j

.. _basics:

############
 The Basics
############

.. important::

   This section is also avaliable in video form `on YouTube <basics_video_>`_.

.. _why_script:

*************
 Why Script?
*************

We have already seen the main *output* from Zeek: logs. But, Zeek has a
whole layer designed to define the logic that creates those logs (and
more!). That is Zeek's scripting language.

We have already seen parts of Zeek script. The :ref:`Providing Script
Values <providing_script_values>` section covered how to pass values
from the command line. We can use this in order to change Zeek's core
functionality from the command line, or from the ``local.zeek`` file in
a cluster.

Zeek scripting is also the core of *detection* logic. You can use Zeek's
scripting language to react to network events, store state about those
events, and then inform incident responders.

We will demonstrate this with a high level example. For this, we will
check if the network traffic contains any malware from the `Team Cymru
Malware hash registry <https://www.team-cymru.com>`_. Should you load
the full script, Zeek will produce a ``notice.log`` entry whenever
it encounters malware hashes, like this:

.. code:: console

   # cat notice.log | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type    file_desc       proto   note    msg     sub     src     dst     p       npeer_descr       actions email_dest      suppress_for    remote_location.country_code    remote_location.region    remote_location.city    remote_location.latitude        remote_location.longitude
   1362692527.080972       CLDH8f3Huq3yGIqjZ6      141.142.228.5   59856   192.150.187.43  <omitted>      text/plain      <omitted>     tcp       TeamCymruMalwareHashRegistry::Match     Malware Hash Registry Detection rate: 95%  Last seen: 2017-01-18 20:34:43 https://www.virustotal.com/gui/search/<omitted>    141.142.228.5   192.150.187.43  80      -       -       Notice::ACTION_LOG        (empty) 3600.000000     -       -       -       -       -

Zeek determined it was malware by looking up the hash in a known
registry---via scripting!

.. literalinclude:: basics/mhr-excerpt.zeek
   :caption:
   :language: zeek
   :tab-width: 4

When Zeek sees a file, it calculates its hash. Whenever that hash is
calculated, it triggers the :zeek:see:`file_hash` event.

The body of our event handler does two things:

#. It checks if we care about this specific file
#. It calls a function (``do_mhr_lookup``) to check the registry.

This leaves out the core of the script, but we introduced one of Zeek's
core concepts already: events. We'll see more of those later. First, we
have to understand the types you can use when scripting.

.. _basics_types:

*******
 Types
*******

Network Types
=============

Zeek monitors network traffic, so its scripting language makes that easy
with custom types. Network types are primitive types within Zeek, so you
can treat addresses, ports, and subnets as native data:

.. literalinclude:: basics/types_network.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

These are some of Zeek's most powerful types. They allow script writers
to easily use common networking language in order to write network
detections.

For more information on each, see documentation for :zeek:see:`addr`,
:zeek:see:`subnet`, and :zeek:see:`port`.

Time Types
==========

When writing Zeek scripts, it's also important to know *when* something
occurred. Zeek provides time values as native types:

.. literalinclude:: basics/types_time.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

The :zeek:see:`current_time` call gets the "wall clock" time when it is
called. The time types are useful for more, though. You can cause some
data to *expire* after a certain interval with :zeek:see:`&create_expire`,
or schedule events to execute some time in the future with
:zeek:see:`schedule`.

For more information, see :zeek:see:`time` and :zeek:see:`interval`.

Container Types
===============

If you have many elements, you can pick one of Zeek's container types to
work with it:

-  :zeek:see:`vector`: Store many ordered elements
-  :zeek:see:`set`: Store many unique elements with fast lookup, unordered
   by default
-  :zeek:see:`table`: Store key-value pairs, unordered by default

Vectors are useful for maintaining ordered lists. Use them to store
sequences of items, like storing mail servers for a domain in order of
preference:

.. literalinclude:: basics/types_vector.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Sets are useful for checking membership. They represent a unique
collection of items (like an allow list or deny list). Here, we create a
set of "safe" ports that are allowed:

.. literalinclude:: basics/types_set.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Tables are useful for mapping keys to values. You may associate a
specific IP address with the number of active connections, a timestamp,
or a username.

Here we use a table to assign human-readable names to IP addresses:

.. literalinclude:: basics/types_table.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

For more information, see :zeek:see:`vector`, :zeek:see:`set`, and
:zeek:see:`table`.

.. _writing-scripts-connection-record:

Record Types
============

Records are just collections of named values---like a ``struct`` in C.
Zeek uses records liberally in order to provide structured data and pass
it amongst events. The most used record is the ``connection`` record,
which represents everything Zeek determined for a given connection.

You can get data from the record with the ``$`` operator. The following
script will use the :zeek:see:`new_connection` event and print who the
connection is between:

.. literalinclude:: basics/types_connection.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

For example, here is the output for the capture file from the
:ref:`Quickstart <quickstart>`:

.. code:: console

   Found connection between 192.168.1.8 and 192.0.78.212
   Found connection between 192.168.1.8 and 192.0.78.150

.. note::

   Zeek's notions of originator and responder aim to capture the natural
   roles of connection endpoints given the protocol information
   observed. They differ from the packet-level concepts of source and
   destination, as well as from higher-level abstractions such as client
   and server.

   Zeek's protocol analyzers determine originator and responder when
   establishing connection state, with the sender of the initial packet
   usually becoming the originator and the recipient becoming the
   responder. However, analyzers may subsequently *flip* the roles if
   protocol semantics suggest it. For example, in the presence of packet
   loss the first observed packet in a DNS transaction may indicate that
   it is in fact the response to a missing query. Zeek's DNS analyzer
   will flip the endpoint roles, making the sender of this packet the
   connection's responder.

The ``connection`` record carries around the state from the connection.
Scripts can add state to this record in order to piece together what
they need, like how Zeek's HTTP scripts correlate requests and responses
with the connection record. The added state is often declared as
:zeek:see:`&optional`, so you should use ``?$`` to make sure the record
contains that field before accessing it. Here, we use ``?$`` to ensure
the connection has HTTP state in the :zeek:see:`http_request` event:

.. literalinclude:: basics/types_connection_http.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Make sure you don't access an optional field without checking if it
exists with ``?$`` first, otherwise your script will encounter an
expression error.

Sometimes you need to bundle your own data. This example defines an
``Asset`` record that groups IP addresses with some useful data:

.. literalinclude:: basics/types_record.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

For more information, see the :zeek:see:`connection` record, or
:zeek:see:`record` for records generally.

Standard Types
==============

Zeek provides many of the standard types expected in a programming
language:

.. literalinclude:: basics/types_standard.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

You can use these for many of the same tasks you would use a general
purpose language for.

For more information, see :zeek:see:`int`, :zeek:see:`count`,
:zeek:see:`bool`, :zeek:see:`string`, and :zeek:see:`pattern`.

You can read more about how these types can be used to change the
program's control flow with :zeek:see:`for` and :zeek:see:`if`.

.. _basics_visibility_scope:

**********************
 Visibility and Scope
**********************

Local and Global
================

So far, we have kept state *within* events with the ``local`` keyword.
When a variable is declared as ``local``, it cannot be used outside of
its scope. But, you can store state *between* events with globals. The
following example stores how many times the :zeek:see:`new_connection`
event gets triggered and prints its result at the end in the
:zeek:see:`zeek_done` event:

.. literalinclude:: basics/scope_global.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

You may have also noticed that the loop from the vector type section
use creates a ``server_ip`` variable without using ``local``:

.. literalinclude:: basics/types_vector.zeek
   :caption:
   :language: zeek
   :start-at: Loop with a 'for'
   :end-at: }
   :lineno-match:
   :emphasize-lines: 3
   :tab-width: 4

The ``server_ip`` variable is actually a ``local`` variable *outside*
the ``for`` loop---just without the keyword. You cannot have two
``local`` variables with the same name in the function scope---therefore,
you can't later use the ``server_ip`` variable name in a new ``local``
variable.

For more information, see :zeek:see:`local` and :zeek:see:`global`.

Exporting
=========

You may expose constants, types, options, and more to other scripts by
putting them in ``export`` blocks. The following example defines a list
of IP addresses in an allow list. If an IP address outside of those is
in a new connection, then we print a warning:

.. literalinclude:: basics/scope_export.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

As-is, running this on the quickstart pcap says one of the addresses is
not allowed:

.. code:: console

   Address 192.0.78.212 is not allowed!
   Address 192.0.78.150 is not allowed!

If we can't change the original script, we can create a new script and
use that!

.. literalinclude:: basics/scope_use_export.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

With this change, nothing will print---all addresses were allowed.

Redef
=====

We can change more than just native variables. In fact, you can use
:zeek:see:`redef` to do far more. When you redefine something with
``redef``, that change is set in stone after Zeek initializes. First,
we will use ``redef`` to demonstrate one of the most powerful features
in Zeek: redefining the ``connection`` record. Later, we will see how
constructs can declare that they may be redefined.

In this example, we want to flag specific connections in the logs so
that we can find them easily later. So, we will add a ``denied`` field:

.. literalinclude:: basics/scope_redef_connection.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

As-is, this script will just print the flag. But, since the
``new_connection`` event is called at the beginning of the connection,
future analyzers can check this ``denied`` flag and use it in their
analysis! The state sticks around.

We can also modify the script slightly to log the flag in ``conn.log``:

.. literalinclude:: basics/scope_redef_connection_log.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4
   :emphasize-lines: 8,15,20

There are three changes here, which are highlighted in order:

#. The ``redef`` redefines :zeek:see:`Conn::Info` instead of
   ``connection``.

#. The ``denied`` field is marked with the :zeek:see:`&log` attribute.

#. We modify ``c$conn`` (which is a ``Conn::Info`` instance) instead of
   ``c``. ``c`` is the container for the whole connection state. Inside
   it, ``c$conn`` is the specific record that gets written to
   ``conn.log``.

By convention, analyzers which log use ``Info`` records to store the
state that they wish to log. ``conn.log`` is no different. So, if you
want to change what goes in ``conn.log``, you add fields to
``Conn::Info``.

.. note::

   The :zeek:see:`&log` attribute tells Zeek that when this record gets
   logged, write this field to that log. Fields must state that they want
   to get logged by opting-in. Attributes in Zeek are a common way to
   add functionality to various language elements. You may control
   whether a field is optional, add an expiration timeout, and much more.
   For more information, see the :ref:`attributes section <attributes>`.

When we run this on the quickstart pcap, we can see that ``conn.log``
now has a ``denied`` field:

.. code:: console

   # zeek basics/scope_redef_connection_log.zeek -Cr traces/quickstart.pcap
   # cat conn.log | zeek-cut -m denied
   denied
   T
   T

Using ``&redef``
----------------

This is possible with the ``&redef`` attribute. If you're writing a
library and want to allow users to customize parts, you may include
``&redef`` to allow extra fields in the record, to log more fields, or
just to configure a constant.

.. literalinclude:: basics/scope_redef_attr.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

This example is a bit contrived, but any users who load the script with
:zeek:see:`@load` can then customize these variables.

For more information, see :zeek:see:`redef` and :zeek:see:`&redef`. Also look
at :zeek:see:`option` and :zeek:see:`const` for some more ways to customize
libraries via ``redef``.

.. _basics_events_functions:

**********************
 Events and Functions
**********************

Events
======

Throughout this section, we have used events such as :zeek:see:`zeek_init`
and :zeek:see:`new_connection`. Zeek itself executes through a series of
events in a queue. For example, when Zeek sees an HTTP request in some
network traffic, it triggers the :zeek:see:`http_request` event. HTTP
scripts may then use that event in order to gather data, correlate a
request with a response, and more. This is core to Zeek's execution.

Zeek does this by placing events into an ordered event queue. Then,
*handlers* get triggered in a first-come-first-served basis. In our
examples above, we only ever used one event at a time, but really there
can be many handlers for a single event:

.. literalinclude:: basics/event_multiple_handlers.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

These events just happen to be in the same file. You can guarantee
ordering events with the :zeek:see:`&priority` attribute:

.. literalinclude:: basics/event_multiple_handlers_priority.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Imagine Zeek analyzing network traffic, and as it does so, it raises
events so that you can react to what was just seen. The DNS analyzer
raises :zeek:see:`dns_request` events when DNS requests are seen, the file
analyzer raises ``file_hash`` when a file hash is computed, and many
more.

You may even choose to trigger an event from a script with the ``event``
statement:

.. literalinclude:: basics/event_statement.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

This is the only way to trigger an event in a script. They do not get
immediately executed, and they cannot return values. Don't think of
events as functions that runs *now*, think of them as interesting things
that will be handled later.

For more information, see :zeek:see:`event`.

Functions
=========

From other programming languages, functions are exactly what you expect:
you can call them to immediately execute some statements in-order. In
this example, imagine you need to check if a certain connection is
internal. The function helps contain the necessary logic in its own
section:

.. literalinclude:: basics/functions.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

You may also use a function to modify container values. In this example,
we modify ``host`` within a separate function:

.. literalinclude:: basics/functions_pass_by_reference.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

The most important part here is that only certain types in Zeek are
"pass by reference." You may pass types like a ``table`` or ``record``
into a function by reference, so that function may modify its values.
But, if you pass a ``count``, then the function will modify a *copy*,
not the original. Try modifying the above script to pass
``host$scanned_count`` in by value and see that it doesn't get updated.

For more information, see :zeek:see:`function`.

Async Functions
===============

.. note::

   Asynchronous functions are a relatively advanced concept, but
   important to understand the detection script from the beginning.

Some functions may take some time to complete, so Zeek should not wait
for it to complete before continuing with its execution. Zeek provides a
``when`` keyword in order to wait for that result, then make it
available when it's ready. In this example, we use ``when`` in order to
lookup the DNS TXT record from ``www.zeek.org``:

.. literalinclude:: basics/functions_async.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

You don't have to understand the specifics here. If a function is
"asynchronous" then you must use ``when`` in order to wait for its
result without blocking Zeek's execution. If you removed the ``when`` in
the previous example, Zeek will error:

.. code:: console

   error in ./functions_async.zeek, line 8: lookup_hostname_txt() can only be called inside a when-condition (lookup_hostname_txt(www.zeek.org))

For more information, see :zeek:see:`when`.

.. _basics_real_script:

*****************************
 Understanding a Real Script
*****************************

Now, we have the tools to understand the detect-mhr script from before.
At the beginning, we only showed the ``file_hash`` event contents. The
logic for the event was mostly within ``do_mhr_lookup``, which is a
function call. Here is that function in its entirety, then we will go
through the entire script and explain each part:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :start-at: do_mhr_lookup
   :end-before: file_hash

First, the function itself takes the hash (provided from ``file_hash``)
and a :zeek:see:`Notice::FileInfo`:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :lines: 38

Then, we declare a ``local`` variable that holds the URL we look up:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :lines: 40

This variable is used in the ``when`` statement to look it up
asynchronously:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :lines: 42

The ``when`` statement has an extra section here, within square brackets
``[]``. That specifies that the block can use ``hash``, ``fi``, and
``hash_domain`` from the outer ``do_mhr_lookup`` function. Without it,
we could not later use ``hash`` in the ``when`` block. Because the code
inside ``{}`` runs later (potentially after the function has finished),
Zeek needs to copy these variables so that they are alive within the
``when`` block.

Next, we use the result within the ``when`` block in order to check the
data:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :lines: 44-49

The data in ``MHR_answer`` is just the result from the DNS lookup, split
at a space. It is a vector, from :zeek:see:`split_string1`. If the answer
has two elements, that means the split was successful, so we can move on
with the logic.

We then convert the string in ``MHR_answer[1]`` (the second element of
the ``vector of string``) into a ``count`` and put it into
``mhr_detect_rate``.

Now, we check if that detection rate is high enough to trigger a notice:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :lines: 51

This is using some ``notice_threshold`` declared as an ``option`` in the
``export`` block above, so users may configure its value.

If it's above the threshold, we have decided to trigger a notice. This
uses Zeek's notice framework, but most of the concepts should be pretty
familiar. In this instance, we are mostly just manipulating the
``string`` to make the notice human-readable:

.. literalinclude:: basics/detect-MHR.zeek
   :caption:
   :language: zeek
   :lineno-match:
   :tab-width: 4
   :lines: 53-61

You can read more about Zeek's notice framework in the :ref:`Notice
Framework <notice-framework>` section. Note that :zeek:see:`NOTICE` is just
a function.

With that, we went from zero to understanding a full Zeek script. In the
next section, we will build up a script from scratch, using what we
learned here.
