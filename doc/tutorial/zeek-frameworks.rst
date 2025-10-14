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

   .. code::

      signature http-reply-body-matcher {
              http-reply-body /.*<body>/
              event "Found reply!"
      }

The pattern in ``http-reply-body`` will simply match on the HTTP
replies. It’s the same sort of pattern as before, but it starts with a
``.*`` to match an arbitrary number of characters before seeing
``<body>``.

Scripting is very straightforward:

   .. code:: zeek

      @load-sigs ./match.sig

      event signature_match(state: signature_state, msg: string, data: string, end_of_match: count) {
          print msg;
      }

Run that on the quickstart pcap:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -r quickstart.pcap
      Found reply!
      Found reply!

You can access the HTTP state in the same way as in the scripting
tutorial in order to increment the patterns. Here’s that script:

   .. code:: console

      @load-sigs ./match.sig

      redef record HTTP::Info += {
              num_entity_matches: count &default=0 &log;
      };

      event signature_match(state: signature_state, msg: string, data: string,
          end_of_match: count)
              {
              if ( state$conn?$http )
                      state$conn$http$num_entity_matches += 1;
              }

As-is, if you run it, just the <body> signature will match:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -r quickstart.pcap
      root@zeek-tutorial:/opt $ cat http.log | zeek-cut num_entity_matches
      1
      1

But you can add another signature:

   .. code::

      signature http-reply-body-matcher2 {
              http-reply-body /.*301 Moved Permanently/
              event "Found reply!"
      }

Then see both match:

   .. code:: console

      root@zeek-tutorial:/opt $ zeek -r quickstart.pcap
      root@zeek-tutorial:/opt $ cat http.log | zeek-cut num_entity_matches
      2
      2

This is quite different from the scripting tutorial, but you can see
that Zeek’s frameworks make otherwise substantial tasks into easy ones.
These signature matches can be used for many things, such as matching
patterns from known vulnerabilities. But, they’re less configurable than
Zeek’s patterns. It’s a different tool.
