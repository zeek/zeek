.. _tutorial-example:

*****************************
 HTTP Entity Patterns Script
*****************************

For this tutorial, we will build a script which searches for certain
patterns in HTTP entities. These will be in a list of “interesting
patterns” that the user can provide. Then, we will augment the HTTP log
with the number of matches. This particular script will be very slow, so
not a production-level analysis, but it will help show many of the core
principles of Zeek scripts and augmenting logs.

Zeek’s scripting language is event based. As network traffic is
processed, events get triggered. When making a script, the author has to
decide what to react to. For this case, we care about HTTP “entities” -
the body of the request or response.

We can find the corresponding event by looking through the HTTP protocol
documentation. TODO: I really have troubles explaining how to find the
correct event. I would imagine people have troubles finding the right
event so… yeah.

In this case, we care about HTTP entities, so the ``http_entity_data``
event is promising. This event can provide a ``string`` containing the
data from the entity. Its signature is:

.. code:: zeek

   event http_entity_data(c: connection, is_orig: bool, length: count, data: string)

Given this, we can see how a package might look. Users can use the
``print`` statement in order to print a given object. In this case,
let’s print the data directly:

   .. code:: zeek

      # test.zeek

      event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
        print data;
      }

NOTE: This (and many other programming tutorials) use printing in order
to demonstrate functionality. However, it’s important to note that this
is almost entirely a tool for debugging. Production-grade scripts should
use other tools such as logging or the notice framework in order to
convey information.

Save that in a file ``test.zeek``. Then, open another terminal in the
container (TODO: Explain how to have 2 sessions in Docker). We will run
Zeek in the first:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -C -i eth0 test.zeek
      listening on eth0

and then ``curl`` in the other:

   .. code:: console

      root@zeek-tutorial:/opt $ curl example.com

You should see *both* windows with the HTML content. One immediately
noticeable difference is that many characters are replaced with hex
codes in the Zeek output. Another is noticeable with large web pages, or
by `redef`-ing a variable.

Try the same thing, except change the Zeek invocation to include a
redefinition for ``http_entity_data_delivery_size``:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -C -i eth0 test.zeek http_entity_data_delivery_size=10
      listening on eth0

and in the other terminal:

   .. code:: console

      root@zeek-tutorial:/opt $ curl example.com

Zeek’s output will look different - namely, every 10 bytes, there should
be a newline. This event gets called in batches for large files. If
we’re looking for a certain pattern, we have to reassemble the complete
data, just in case the pattern spans multiple lines. That will be the
first step.

Reassembling HTTP Entities
==========================

Thankfully, Zeek provides a convenient way to store state between event
calls within the same connection: The connection record!

Most (TODO: All?) protocols append a record to the connection record in
order to store its state. For HTTP (TODO: all?) protocols, this record
is called ``State``. Not only does this store information that the
analyzer uses, we can also append our own fields to it for various
purposes. We will use the ``redef`` keyword for this.

Above the ``http_entity_data`` event, let’s add a string to keep track
of the entity data we’ve seen so far:

   .. code:: zeek

      redef record HTTP::State += {
          entity: string &default="";
      };

This statement will take the ``HTTP::State`` record mentioned before and
add a field to it. When fields get added, they must have either
``&default`` (which specifies the default value) or ``&optional`` (which
means you don’t need to initialize the field if you don’t want to). In
this case, we have a simple default that we can use to “build up” the
entity, so we use default. The default ``entity`` value gets created
whenever the ``HTTP::State`` record is created by the HTTP analyzer. The
HTTP analyzer doesn’t need to know that we just appended a field to its
record.

Then, we can modify the event handler to add the data to this for each
event:

   .. code:: zeek

      # test.zeek

      event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
          c$http_state$entity += data;
          print c$http_state$entity;
      }

Inside the event, we have two new statements. The first is where most of
the magic happens. For Zeek scripting, the ``$`` separates field values.
This is often ``.`` in other languages (like ``my_class.my_field``). We
then use the ``+=`` operator to concatenate the ``data`` string to
what’s in that field.

The other key here is that ``connection`` object. The connection record
(that is, the first argument to the event) carries around state for the
connection. Different protocols will use the same ``redef`` trick, but
for the ``connection`` record, in order to carry around its data. You
can see which fields an analyzer adds to the ``connection`` object in
the “redefinitions” section in the script’s documentation - here for
HTTP. You can see from that section that the HTTP analyzer adds a
variable ``http_state`` with type ``HTTP::State`` to the ``connection``
record - thus, we can use it!

Before we use it, since ``c$http_state`` is an optional field, it could
be necessary to ensure that the ``c$http_state`` field exists before
using it. If you use an optional field without it being present, that
would be an error:

   .. code:: console

      expression error in ./test.zeek, line 7: field value missing (c$http_state)

Therefore, we should wrap anything that uses ``http_state`` with a field
value existence check with ``?$``:

   .. code:: zeek

      event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
          if ( c?$http_state ) {
              c$http_state$entity += data;
              print c$http$entity;
          }
      }

This should get exactly the same results as before. If you want to test
it, you can use ``delete c$http_state;`` before the ``if`` statement in
order to make sure it’s not set when it gets to that point, even though
it always should be.

This prints the information as it is getting collected. Instead, it
should only print once at the end. For this, we can use the
``http_end_entity`` event. Remove the `print` that is in
``http_entity_data`` and move it to the ``http_end_entity`` event:

   .. code:: zeek

      event http_end_entity(c: connection, is_orig: bool, length: count, data: string) {
          if ( c?$http_state ) {
              print c$http_state$entity;
          }
      }

TODO: Should we also reset $entity here?

Now, it will only print once - at the end of an entity.

TODO: Can entities be nested? I think not but entities.zeek deals with a
depth and I really don’t want to. :)

There is one more caveat. This gives theoretically unbounded state
growth, as `entity` has no upper bound. We should introduce an upper
bound that users can configure. This is easy with redefineable options!

First, we declare the option at the top of the file in an ``export``
block:

   .. code:: zeek

      export {
        option max_reassembled_entity_size: int = 10000 &redef;
      }

.. note::

   Zeek has two main types for numbers: ``int`` (if it can be negative)
   and ``count`` (if it cannot be negative). The
   ``max_reassembled_entity_size`` is an ``int`` - but it should not be
   negative! This makes Zeek understand that the *result* of any
   calculations using this number may also be negative. Thus, later,
   when we subtract another ``count``, this number may be negative. If
   it were a ``count``, there is potential for that result to
   "underflow" and become a very large number instead - which would be a
   bug.

   Also note, options can be changed, but only through specific
   mechanisms. See the (TODO: link) option declaration documentation for
   more information.

Then, we want to reach exactly that entity size, but never exceed it.
You can use ``|...|`` around a string to get its size, like
``|c$http_state$entity|`` will get the length of the string in that
field. You can do the same to get the size of most containers, like a
vector. If we subtract it from ``max_reassembled_entity_size``, that
should be the remaining length:

   .. code:: zeek

      local remaining_available = max_reassembled_entity_size - |c$http_state$entity|;
      if (remaining_available <= 0) return;

This will go inside the ``if`` block from before, but shown here for
demonstration purposes.

The ``local`` keyword just means that ``remaining_available`` will not
be usable outside of the current scope - which will be the ``if`` block.

Next, we will just decide how much of ``data`` to add depending on
``length``:

   .. code:: zeek

      if (length <= remaining_available)
        c$http_state$entity += data;
      else
        c$http_state$entity += data[:remaining_available];

Where the subscript operator (in ``data[:remaining_available]``) allows
extracting just the substring if we only want part of the provided data.

The full script at this point is here for your convenience. This is also
available in the Docker image in
``/opt/scripting-tutorial/01-http-entities.zeek``:

.. literalinclude:: tutorial/01-http-entities.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Searching for Patterns
======================

Now, we have all of the data in a given entity stored in
c$http_state$entity. We may want to examine that reassembled data for
certain patterns. Then, just for completeness, we can log how many of
those patterns matched entities in the HTTP connection.

Patterns in Zeek are built on regular expressions - they can be used to
find matches within a larger string. They are enclosed by forward
slashes (``/``). You can read more about them here.

We want to find specific strings within the HTTP entity, so this is
perfect. First, let’s see how you would search for a pattern in HTTP
traffic. In ``http_end_entity`` we print the entity, let’s change that
to print if some pattern matched:

   .. code:: zeek

      event http_end_entity(c: connection, is_orig: bool) {
          if (c?$http_state) {
              print /Will not match!/ in c$http_state$entity;
          }
      }

Running this on the quickstart pcap will yield no matches:

   ..
      code: console

      root@zeek-tutorial:/opt $ zeek -Cr traces/quickstart.pcap scripting-tutorial/01-http-entities.zeek
      F
      F
      F
      F

Note that in Zeek, true and false are represented by single-character
``T`` and ``F`` respectively.

We can change this script to actually match, say with a ``<body>`` tag:

   ..
      code: console

      root@zeek-tutorial:/opt $ zeek -Cr traces/quickstart.pcap scripting-tutorial/01-http-entities.zeek
      F
      T
      F
      T

TODO: Include first characters and explain that some are empty

At this point, we need:

A list of user-provided patterns to match How many of those patterns
matched the entity content

The first is easy, it’s similar to the ``max_reassembled_entity_size``
from before. Just put a vector in the export block with ``&redef``:

   .. code:: zeek

      const http_entity_patterns: vector of pattern = {/Will not match!/, /<body>/, /301 Moved Permanently/} &redef;

Then part 2 can be done in a function that takes the content and returns
the number of patterns that matched. Functions are defined similar to
events, just with the ``function`` keyword. These have to be explicitly
called in your Zeek scripts. Here is the function signature:

   .. code:: zeek

      function num_entity_pattern_matches(state: HTTP::State): count {

This function takes in a single HTTP::State as a parameter and returns a
count - easy enough. One important point is that this function’s
parameter is not the entity itself, but the HTTP state. This is because
atomic values (like counts, addresses, and strings) are passed by
*value* in Zeek. That means if the entity was passed in as a string, it
would get copied, which could be very expensive. Instead, we pass in the
HTTP state. Types like records or tables are passed by *reference*, so
no copy is necessary.

Now, its implementation simply loops through the patterns in
http_entity_patterns and counts the matches:

   .. code:: zeek

      function num_entity_pattern_matches(state: HTTP::State): count {
          local num_matches = 0;
          for (_, pat in http_entity_patterns) {
              if (pat in state$entity)
                  num_matches += 1;
          }

          return num_matches;
      }

There is one common trip-up in this function: ``for`` loops. In Zeek
scripts, using a for loop often loops over the *indexes* rather than
elements. That’s what the ``_`` in the ``for`` loop is: that’s an unused
index, which would often just count up from 0 each iteration. You can
add a second optional parameter, named ``pat`` in the function, which
contains the actual elements.

NOTE: Add Arne’s suggestion of a table[pattern] as an alternative in a
note?

Finally, call this new function when we finish collecting entity data:

   .. code:: zeek

      event http_end_entity(c: connection, is_orig: bool) {
          if (c?$http_state)
              print num_entity_pattern_matches(c$http_state);
      }

Now, because ``http_entity_patterns`` is marked with ``&redef``, you can
change its contents from other scripts or the command line.

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -Cr traces/quickstart.pcap test.zeek
      0
      2
      0
      2

In this case, we will add three patterns, two of them will match. The
backslash characters (``\``) are used to escape angled brackets, since
this is invoked from a Bash shell:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -Cr traces/quickstart.pcap test.zeek “http_entity_patterns+={/\<html\>/, /Also does not match/, /\<title\>/}”
      0
      4
      0
      4

Finally, we have the core functionality for this script. The full script
at this point is here for your convenience. As before, this is also
available in the Docker image in
``/opt/scripting-tutorial/02-http-patterns.zeek``:

.. literalinclude:: tutorial/02-http-patterns.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Modifying the Logs
==================

This script still prints information. It should, however, convey this
information in Zeek’s “native” form - logs. For this, we will take two
approaches: enriching the existing HTTP log, and using the notice
framework to deliver notices.

TODO: It may be nice to discuss when to use notices or when to add to
logs?

Adding a Log Field
------------------

Adding a log field to Zeek is actually very easy. Since we want to add
to the HTTP log, we will use the record that HTTP logs to - its ``Info``
record. First, we decide what we are logging - in this case, it’s just
the number of pattern matches. So, we add that to the HTTP::Info record
with ``redef``, and mark the field with ``&log`` to make sure it gets
logged:

   .. code:: zeek

      redef record HTTP::Info += {
          num_entity_matches: count &default=0 &log;
      };

Next, in ``http_end_entity``, set the field:

   .. code:: zeek

      event http_end_entity(c: connection, is_orig: bool) {
          if (c?$http_state && c?$http)
              c$http$num_entity_matches += num_entity_pattern_matches(c$http_state);
      }

We’re done! Log enrichment itself is simple - add the field to the
correct record. However, there are more considerations when making a
robust script. For example, there can be multiple entities for a given
HTTP request, so this script simply appends the matches to the previous
value.

If we run Zeek on the quickstart pcap:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -r quickstart.pcap

Then check for our new field in the logs:

   .. code:: console

      root@zeek-tutorial:/opt $ cat http.log | zeek-cut num_entity_matches
      2
      2

We see the matches were logged!

Generating a Notice
-------------------

Zeek also offers notices for various scenarios. These are outlined in
the Notice framework section. These are useful if there is some scenario
users may want to be notified about, like brute forcing passwords.
Notices can then be configured to take a specific action, like send an
email when it is generated. In this case, we will simply use it to raise
a notice when a certain threshold of matches are met.

To do this, first ``redef`` the ``Notice::Type`` with an extra value:

   .. code:: zeek

      redef enum Notice::Type += {
          Entity_Pattern_Threshold,
      };

Then, add another ``redef`` option for this threshold, still in the
export block:

   .. code:: zeek

      option pattern_threshold = 5 &redef;

Finally, we can test if this threshold was exceeded in
``http_end_entity``:

   .. code:: zeek

      event http_end_entity(c: connection, is_orig: bool) {
          if (c?$http_state && c?$http) {
              local num_entity_matches = num_entity_pattern_matches(c$http_state);
              c$http$num_entity_matches += num_entity_matches;
              if (num_entity_matches >= pattern_threshold)
                  NOTICE([$note=Entity_Pattern_Threshold,
                      $msg=fmt("Found %d pattern matches in HTTP entity.", num_entity_matches),
                      $id=c$id,
                      $identifier=cat(num_entity_matches, c$id$orig_h, c$id$resp_h)]);
          }
      }

This threshold only applies to a single entity, so if there are multiple
entities, each may exceed it.

Notices will, by default, get logged in ``notice.log``. You will notice
that no notice log exists when executed as-is:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek test.zeek -r traces/quickstart.pcap
      root@zeek-tutorial:/opt $ cat notice.log
      cat: notice.log: No such file or directory

But, we can lower the threshold:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek test.zeek -r traces/quickstart.pcap pattern_threshold=1
      root@zeek-tutorial:/opt $ cat notice.log
      #separator \x09
      … <cut for brevity>

The notice framework is a powerful way to inform analysts of interesting
events in various ways. For more information, read the section on the
notice framework.

With that, the script is done. Here it is in its entirety, or in
``scripting-tutorial/03-http-logging.zeek``:

.. literalinclude:: tutorial/03-http-logging.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

Conclusions
-----------

We went over how to use many of Zeek’s language features as well as ways
to expose the new analysis to users. There are ways to learn more about
Zeek scripting as well:

You can go through try.zeek.org - this is an interactive tutorial all in
the web browser. It explains Zeek’s functionality with increasingly
advanced scripts. That is a logical next step after this tutorial if
some language features seem under-explained. You can go through the
script reference section. This has detailed explanations of all of
Zeek’s operators, statements, declarations, and more. If you need a
deep-dive, that is the reference to use.

While this script is not necessarily production-capable, it uses Zeek in
many of the same ways you would for a real detection. Part of the reason
it’s not production-capable is that Zeek actually has better ways of
matching patterns on traffic and files - the Signature framework. In the
next section, we will discuss Zeek’s many frameworks and how to use some
of them.
