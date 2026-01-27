.. _tutorial-example:

#######################
 A More Complex Script
#######################

For this tutorial, we will build a script which searches for certain
patterns in HTTP entities. These will be in a list of “interesting
patterns” that the user can provide. Then, we will augment the HTTP log
with the number of matches. This particular script will be very slow, so
not a production-level analysis, but it will help show many of the core
principles of Zeek scripts and augmenting logs.

Recall that Zeek's scripting language is :ref:`event-based <basics_events>`.  As
Zeek processes network traffic, it triggers events.  When making a script, the
author has to decide which events to react to. For this case, we care about HTTP
“entities”: the body of HTTP requests and responses.

We can find the corresponding event by looking through the HTTP protocol
documentation. In this case, we care about HTTP entities, so the
:zeek:see:`http_entity_data` event looks promising. This event
provides a ``string`` containing the entity data. Its signature
is:

.. code:: zeek

   event http_entity_data(c: connection, is_orig: bool, length: count, data: string)

With this information we can see what entities might look like. Users can use the
:zeek:see:`print` statement in order to print a given object. In this case,
let's print the data directly:

.. literalinclude:: tutorial/01-steps/01.zeek
   :caption: :file:`test.zeek`
   :language: zeek
   :tab-width: 4

.. note::

   This (and many other programming tutorials) use printing in order to
   demonstrate functionality. However, it's important to note that in Zeek
   :zeek:see:`print` is almost entirely a tool for debugging. Production-grade scripts
   should use other tools such as logging, the notice framework, or
   Zeek's :doc:`reporter facility </scripts/base/frameworks/reporter/main.zeek>`
   in order to convey information.

Save the above in a file ``test.zeek`` and invoke Zeek on the quickstart pcap:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap test.zeek

This should print the result from trying to access ``zeek.org`` via
HTTP.

.. note::

   In order to keep the tutorial consistent, the examples use a capture file.
   But, in this case, you can test it with live traffic. To do so, first start
   running Zeek on a network interface:

   .. code:: console
   
      # zeek -C -i eth0 test.zeek
      listening on eth0

   Then, open another terminal in the container from the host:

   .. code:: console

      $ docker exec -it zeek-tutorial /bin/bash

   This prompt will be used to generate traffic for Zeek. Now, ``curl`` in
   the new terminal session:

   .. code:: console

      # curl example.com
      <!doctype html>...

   *Both* windows should print HTML content. You can exit the previous Zeek
   invocation with Ctrl+C.

Now, try the same thing, except change the Zeek invocation to include a
redefinition for ``http_entity_data_delivery_size``:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap test.zeek http_entity_data_delivery_size=10

Zeek's output will look different---namely, every 10 bytes, there should
be a newline. The :zeek:see:`http_entity_data` event gets called in
batches for large entities, so Zeek doesn't have to buffer up the entity
in its entirety. Therefore, we must reassemble the complete data
before matching patterns on the entity, just in case the pattern spans
over multiple events. That will be the first step.

****************************
 Reassembling HTTP Entities
****************************

Thankfully, Zeek provides a convenient way to store state between event
calls within the same connection: The :zeek:type:`connection` record!

Many protocols append a record to the connection record in order to
store connection state, either for logging or simply tracking something. For
HTTP, this record is the :zeek:see:`HTTP::State` record. The name
``State`` is convention for protocols which must maintain state for
multiple requests or responses. Not only does this store information
that the analyzer uses, we can also append our own fields to it for
various purposes. We will use the :zeek:see:`redef` keyword for this.

Above the ``http_entity_data`` event, let's add a string to keep track
of the entity data we've seen so far:

.. literalinclude:: tutorial/01-steps/02.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

This statement will take the :zeek:type:`HTTP::State` record mentioned before and
add a field to it. When fields get added, they must have either
``&default`` (which specifies the default value) or ``&optional`` (which
means you don't need to initialize the field if you don't want to).

.. note::

   To see why these are needed, consider pre-existing code that creates an
   :zeek:type:`HTTP::State` instance: it wasn't written with awareness of the new field,
   so Zeek wouldn't know what value to assign it. Either of the attributes
   provides a way out.

In this case, we have a simple default that we can use to “build up” the
entity, so we use ``&default``. The default ``entity`` value gets
created whenever the :zeek:type:`HTTP::State` record is created by the HTTP
analyzer. The HTTP analyzer doesn't need to know that we just appended a
field to its record.

Then, we can modify the event handler to add the data to this for each
event:

.. literalinclude:: tutorial/01-steps/03.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Inside the event, we have two new statements. The first is where most of
the magic happens. For Zeek scripting, the ``$`` separates field values.
This is often ``.`` in other languages (like ``my_class.my_field``). We
then use the ``+=`` operator to concatenate the ``data`` string to
what's in that field.

The other key here is that ``connection`` object. The connection record
(that is, the first argument to the event) carries around state for the
connection. Many protocols will use :zeek:see:`redef` to add extra fields
associated with that protocol---in this case, the HTTP analyzer adds
both an :zeek:type:`HTTP::Info` and :zeek:type:`HTTP::State` field. You can see which
fields an analyzer adds to the ``connection`` object in the
“redefinitions” section in the script's documentation---such as :doc:`here
</scripts/base/protocols/http/main.zeek>` for HTTP. You can see from
that section that the HTTP analyzer adds a variable ``http_state`` with
type :zeek:type:`HTTP::State` to the ``connection`` record---thus, we can use it!

Before we do so, we need to ensure that the ``c$http_state`` field exists before
we use it, since its presence is optional. Using an optional field that's absent
would be a runtime error:

.. code:: console

   expression error in ./test.zeek, line 7: field value missing (c$http_state)

Therefore, we should wrap anything that uses ``http_state`` with a field
value existence check with ``?$``:

.. literalinclude:: tutorial/01-steps/04.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

For every update, this will print the accumulated entity up to that point. If
the entity data is split over multiple event invocations, this will print an
increasingly larger entity chunks.

For testing, try deleting the connection record`s ``http_state`` before
the ``if`` statement. Nothing should print, since you check the
existence of that optional field before printing.

It'd be better to print the entity only once, when complete. For this, we can use the
:zeek:see:`http_end_entity` event. Remove the ``print`` in
``http_entity_data``, and move it to the ``http_end_entity`` event:

.. literalinclude:: tutorial/01-steps/05.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Now, it will only print once---at the end of an entity. We also delete
the entity here, since it's assumed entities can't be nested, so we're
done with it. If you care for nested entities, this would not be
sufficient.

There is one more caveat. This gives theoretically unbounded state
growth, as ``entity`` has no upper bound. We should introduce an upper
bound that users can configure. This is easy with redefineable options!

First, we declare the option at the top of the file in an ``export``
block:

.. literalinclude:: tutorial/01-steps/06.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

.. note::

   Zeek has two main types for numbers: ``int`` (if it can be negative)
   and ``count`` (if it cannot be negative). The
   ``max_reassembled_entity_size`` is an ``int``---but it should not be
   negative! This makes Zeek understand that the *result* of any
   calculations using this number may also be negative. Thus, later,
   when we subtract another ``count``, this number may be negative. If
   it were a ``count``, there is potential for that result to
   "underflow" and become a very large number instead---which would be a
   bug.

   For more information, see the :zeek:type:`count` documentation.

   Also note, options can be changed, but only through specific
   mechanisms. See the :zeek:see:`option` declaration documentation
   for more information.

Then, we want to reach exactly that entity size, but never exceed it.
You can use ``|...|`` around a string to get its size, like
``|c$http_state$entity|`` will get the length of the string in that
field. You can do the same to get the size of most containers, like a
vector. If we subtract it from ``max_reassembled_entity_size``, that
should be the remaining length:

.. literalinclude:: tutorial/01-steps/07.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

The ``local`` keyword just means that ``remaining_available`` will not
be usable outside of the current scope---which will be the ``if`` block.

Next, we will just decide how much of ``data`` to add depending on
``length``:

.. literalinclude:: tutorial/01-steps/08.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Where the subscript operator (in ``data[:remaining_available]``) allows
extracting only the remaining available data if we can only hold part of
it.

The full script at this point is here for your convenience:

.. literalinclude:: tutorial/01-http-entities.zeek
   :caption: :file:`scripts/tutorial/01-http-entities.zeek`
   :language: zeek
   :linenos:
   :tab-width: 4

************************
 Searching for Patterns
************************

Now, we have all of the data in a given entity stored in
``c$http_state$entity``. We may want to examine that reassembled data
for certain patterns. Then, just for completeness, we can log how many
of those patterns matched entities in the HTTP connection.

Patterns in Zeek are built on regular expressions---they can be used to
find matches within a larger string. They are enclosed by forward
slashes (``/``). You can read more about them from the
:zeek:type:`pattern` documentation.

We want to find specific strings within the HTTP entity, so this is
perfect. First, let's see how you would search for a pattern in HTTP
traffic. In ``http_end_entity`` we print the entity, let's change that
to print if some pattern matched:

.. literalinclude:: tutorial/02-steps/02.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

This uses :zeek:see:`fmt` in order to print readable results. See that
BIF's documentation for more information, but it allows similar format
strings to ``printf`` in C.

Running this on the quickstart pcap will yield no matches:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap test.zeek
   Did the pattern '/^?(Will not match!)$?/' match? F
   Did the pattern '/^?(Will not match!)$?/' match? F

Note that in Zeek, true and false are represented by single-character
``T`` and ``F`` respectively.

We can change this script to actually match, say with a ``<body>`` tag:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap test.zeek
   Did the pattern '/^?(<body>)$?/' match? T
   Did the pattern '/^?(<body>)$?/' match? T

At this point, we need:

#. A list of user-provided patterns to match
#. How many of those patterns matched the entity content

The first is easy, it's similar to the ``max_reassembled_entity_size``
from before. Just put a vector in the export block with ``&redef``:

.. literalinclude:: tutorial/02-steps/03.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Then part 2 can be done in a function that takes the content and returns
the number of patterns that matched. Functions are defined similar to
events, just with the ``function`` keyword. These have to be explicitly
called in your Zeek scripts. Here is the function signature:

.. code:: zeek

   function num_entity_pattern_matches(state: HTTP::State): count {

This function takes in a single :zeek:see:`HTTP::State` as a parameter
and returns a count---simple enough. One important point is that this
function's parameter is not the entity itself, but the HTTP state. This
is because atomic values (like counts, addresses, and strings) are
passed by *value* in Zeek. That means if the ``entity`` was passed in
directly, it would get copied, which could be very expensive. Instead,
we pass in the HTTP state. Types like records or tables are passed by
*reference*, so no copy is necessary.

Now, its implementation simply loops through the patterns in
``http_entity_patterns`` and counts the matches:

.. literalinclude:: tutorial/02-steps/04.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

There is one common trip-up in this function: ``for`` loops. In Zeek
scripts, using a for loop often loops over the *indexes* rather than
elements. That's what the ``_`` in the ``for`` loop is: that's an unused
index, which would often just count up from 0 each iteration. You can
add a second optional parameter, named ``pat`` in the function, which
contains the actual elements.

.. note::

   Zeek's native types are quite powerful on their own. For example,
   this case could be done in a similar fashion with a table of
   patterns:

   .. code:: zeek

      function num_entity_pattern_matches(state: HTTP::State): count
      	{
      	local entity_patterns: table[pattern] of count = {
      		[/.*Will not match!.*/s] = 1,
      		[/.*<body>.*/s] = 2,
      		[/.*301 Moved Permanently.*/s] = 3,
      	};

      	return |entity_patterns[state$entity]|;
      	}

   This is a more efficient way to match a large number of known
   patterns. However, there are a few extra considerations that are
   outside of the scope here. For example, since we have newlines in the
   HTTP entities, a ``s`` character is necessary at the end of each
   pattern (see the :zeek:type:`pattern` documentation for more
   information).

   See the :zeek:type:`table` section for more interesting ways to use
   tables, including another "special lookup" for subnets and addresses.

Finally, call this new function when we finish collecting entity data:

.. literalinclude:: tutorial/02-steps/05.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Now, because ``http_entity_patterns`` is marked with ``&redef``, you can
change its contents from other scripts or the command line.

.. code:: console

   # zeek -Cr traces/zeek-doc/quickstart.pcap test.zeek
   Found 2 matches in the HTTP entity
   Found 2 matches in the HTTP entity

In this case, we will add three patterns, two of them will match. The
backslash characters (``\``) are used to escape angled brackets, since
this is invoked from a Bash shell:

.. code:: console

   # zeek -Cr traces/zeek-doc/quickstart.pcap test.zeek "http_entity_patterns+={/\<html\>/, /Also does not match/, /\<title\>/}"
   Found 4 matches in the HTTP entity
   Found 4 matches in the HTTP entity

Finally, we have the core functionality for this script. The full script
at this point is here for your convenience.

.. literalinclude:: tutorial/02-http-patterns.zeek
   :caption: :file:`scripts/tutorial/02-http-patterns.zeek`
   :language: zeek
   :linenos:
   :tab-width: 4

********************
 Modifying the Logs
********************

This script still prints information. It should, however, convey this
information in Zeek's “native” form---logs. For this, we will take two
approaches: enriching the existing HTTP log, and using the notice
framework to deliver notices.

Adding a Log Field
==================

Adding a log field to Zeek is actually very simple. Since we want to add
to the HTTP log, we will use the record that HTTP logs to---its ``Info``
record. First, we decide what we are logging---in this case, it's just
the number of pattern matches. So, we add that to the
:zeek:see:`HTTP::Info` record with ``redef``, and mark the field with
``&log`` to make sure it gets logged:

.. literalinclude:: tutorial/03-steps/02.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Next, in ``http_end_entity``, set the field:

.. literalinclude:: tutorial/03-steps/03.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

We're done! Log enrichment itself is simple---add the field to the
correct record. However, there are more considerations when making a
robust script. For example, there can be multiple entities for a given
HTTP request, so this script simply appends the matches to the previous
value.

Now we can just run the script on the quickstart pcap and check the log:

.. code:: console

   # zeek -r traces/zeek-doc/quickstart.pcap test.zeek
   # cat http.log | zeek-cut -m num_entity_matches
   num_entity_matches
   2
   2

We see the matches were logged!

Generating a Notice
===================

Zeek also offers notices for various scenarios. These are outlined in
the Notice framework section. These are useful if there is some scenario
users may want to be notified about, like brute forcing passwords.
Notices can then be configured to take a specific action, like send an
email when it is generated. In this case, we will simply use it to raise
a notice when a certain threshold of matches are met.

To do this, first ``redef`` the ``Notice::Type`` with an extra value:

.. literalinclude:: tutorial/03-steps/04.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Then, add another ``&redef`` option for this threshold, still in the
export block:

.. literalinclude:: tutorial/03-steps/05.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

Finally, we can test if this threshold was exceeded in
``http_end_entity``:

.. literalinclude:: tutorial/03-steps/06.zeek.diff
   :caption: :file:`test.zeek`
   :language: diff
   :start-after: @@
   :tab-width: 4

This threshold only applies to a single entity, so if there are multiple
entities, each may exceed it.

Notices will, by default, get logged in ``notice.log``. You will notice
that no notice log exists when executed as-is:

.. code:: console

   # zeek test.zeek -r traces/zeek-doc/quickstart.pcap
   # cat notice.log
   cat: notice.log: No such file or directory

.. note::

   If ``notice.log`` exists, it may be from a previous invocation. Try
   removing it and executing ``zeek`` again.

But, we can lower the threshold:

.. code:: console

   # zeek test.zeek -r traces/zeek-doc/quickstart.pcap pattern_threshold=1
   # cat notice.log | zeek-cut -m
   ts      uid     id.orig_h       id.orig_p       id.resp_h       id.resp_p       fuid    file_mime_type      file_desc       proto   note    msg     sub     src     dst     p       n  peer_descr       actions email_dest      suppress_for    remote_location.country_code    remote_location.region      remote_location.city    remote_location.latitude        remote_location.longitude
   1747147647.735035       -       192.168.1.8     52917   192.0.78.212    80      -       -  -tcp     Entity_Pattern_Threshold        Found 2 pattern matches in HTTP entity. -       192.168.1.8 192.0.78.212    80      -       -       Notice::ACTION_LOG      (empty) 3600.000000--       -       -       -
   1747147654.341780       -       192.168.1.8     52918   192.0.78.150    80      -       -  -tcp     Entity_Pattern_Threshold        Found 2 pattern matches in HTTP entity. -       192.168.1.8 192.0.78.150    80      -       -       Notice::ACTION_LOG      (empty) 3600.000000--       -       -       -

The notice framework is a powerful way to inform analysts of interesting
events in various ways. For more information, read the :doc:`Notice
framework </frameworks/notice>` section.

With that, the script is done. Here it is in its entirety:

.. literalinclude:: tutorial/03-http-logging.zeek
   :caption: :file:`scripts/tutorial/03-http-logging.zeek`
   :language: zeek
   :linenos:
   :tab-width: 4

Conclusions
===========

We just covered many of Zeek's language features, as well as ways to expose a
new analysis' results to users. There's a lot more to cover:

Explore the tutorial at `try.zeek.org <https://try.zeek.org>`_---this is an
interactive tutorial all in the web browser. It explains Zeek's
functionality with increasingly advanced scripts. That is a logical next
step after this tutorial if some language features seem under-explained.
You can go through the :doc:`script reference </reference/zeekscript/index>`
section. This has detailed explanations of all of Zeek's :doc:`operators
</reference/zeekscript/operators>`, :doc:`statements
</reference/zeekscript/statements>`, :doc:`attributes
</reference/zeekscript/attributes>`, and more. If you need a deep-dive, that
is the reference to use.

While this script is not necessarily production-ready, it uses Zeek in many of
the same ways you would for a real detection. In it, we've briefly touched
several of Zeek's commonly used frameworks, and you should :doc:`explore them
</frameworks/index>` to understand Zeek's broader capabilities.
