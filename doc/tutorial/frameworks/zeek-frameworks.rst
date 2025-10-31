.. _zeek-frameworks:

###################
 Zeek's Frameworks
###################

Zeek provides various “frameworks” to extend its capabilities. You can
read about each framework in detail in the frameworks section. Here are
some commonly used frameworks:

-  Cluster framework - distributes traffic across multiple processes and
   hosts
-  Input framework - imports data into Zeek
-  Logging framework - change what gets logged and how
-  Notice framework - custom alerts from traffic

Frameworks are a relatively loose collection. They are simply built-in
ways of solving common problems. Some are ingrained into parts of Zeek’s
core, such as the cluster framework. Others are more tools for achieving
specific goals, like the input framework. In this section, we will use a
framework specifically for matching on various inputs: the signature
framework.

*************************************
 Patterns in the Signature Framework
*************************************

The signature framework works on signatures like this:

.. code::

   signature my-first-sig {
       ip-proto == tcp
       dst-port == 80
       payload /.*root/
       event "Found root!"
   }

Then you save that in a file like ``mysigs.sig``. You load this from a
Zeek script, then you get events whenever that signature matches. Let’s
use it for HTTP entities.

First, we need to make a signature. That signature will just match on
HTTP replies (that way it’s equivalent for the quickstart pcap). It’s
quite simple:

.. literalinclude:: framework-scripts/match.sig
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4
   :end-before: http-reply-body-matcher2

The pattern in ``http-reply-body`` will simply match on the HTTP
replies. It’s the same sort of pattern as before, but it starts with a
``.*`` to match an arbitrary number of characters before seeing
``<body>``.

Scripting is very straightforward:

.. code:: zeek

   # match.zeek
   @load-sigs ./match.sig

   event signature_match(state: signature_state, msg: string, data: string, end_of_match: count) {
       print msg;
   }

Run that on the quickstart pcap:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek -r traces/zeek-doc/quickstart.pcap match.zeek
   Found reply!
   Found reply!

You can access the HTTP state in the same way as in the scripting
tutorial in order to increment the patterns. Here’s that script:

.. literalinclude:: framework-scripts/match.zeek
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4

As-is, if you run it, just the <body> signature will match:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek -r traces/zeek-doc/quickstart.pcap match.zeek
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ cat http.log | zeek-cut num_entity_matches
   1
   1

But you can add another signature:

.. literalinclude:: framework-scripts/match.sig
   :caption:
   :language: zeek
   :linenos:
   :tab-width: 4
   :start-at: http-reply-body-matcher2

Then see both match:

.. code:: console

   root@zeek-tutorial:/opt/zeek-tutorial-setup $ zeek -r traces/zeek-doc/quickstart.pcap match.zeek
   root@zeek-tutorial:/opt/zeek-tutorial-setup $ cat http.log | zeek-cut num_entity_matches
   2
   2

This is quite different from the scripting tutorial, but you can see
that Zeek’s frameworks make otherwise substantial tasks into easy ones.
These signature matches can be used for many things, such as matching
patterns from known vulnerabilities. But, they’re less configurable than
Zeek’s patterns. It’s a different tool.
