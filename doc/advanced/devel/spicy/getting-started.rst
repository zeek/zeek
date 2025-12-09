
===============
Getting Started
===============

Spicy's own :spicylink:`Getting Started <getting-started.html>` guide
uses the following Spicy code to parse a simple HTTP request line:

.. literalinclude:: examples/my-http.spicy
   :lines: 4-
   :caption: my-http.spicy
   :language: spicy

While the Spicy documentation goes on to show :spicylink:`how to use
this to parse corresponding data from the command line
<getting-started.html#a-simple-parser>`, here we will instead leverage
the ``RequestLine`` parser to build a proof-of-concept protocol
analyzer for Zeek. While this all remains simplified here, the
following, more in-depth :ref:`spicy_tutorial` demonstrates how
to build a complete analyzer for a real protocol.

.. rubric:: Preparations

Because Zeek works from network packets, we first need a packet trace
with the payload we want to parse. We can't just use a normal HTTP
session as our simple parser wouldn't go further than just the first
line of the protocol exchange and then bail out with an error. So
instead, for our example we create a custom packet trace with a TCP
connection that carries just a single HTTP request line as its
payload::

    # tcpdump -i lo0 -w request-line.pcap port 12345 &
    # nc -l 12345 &
    # echo "GET /index.html HTTP/1.0" | nc localhost 12345
    # killall tcpdump nc

This gets us :download:`this trace file <examples/request-line.pcap>`.

.. _example_spicy_my_http_adding_analyzer:

.. rubric:: Adding a Protocol Analyzer

Now we can go ahead and add a new protocol analyzer to Zeek. We
already got the Spicy grammar to parse our connection's payload, it's
in ``my-http.spicy``. In order to use this with Zeek, we have two
additional things to do: (1) We need to let Zeek know about our new
protocol analyzer, including when to use it; and (2) we need to define
at least one Zeek event that we want our parser to generate, so that
we can then write a Zeek script working with the information that it
extracts.

We do both of these by creating an additional control file for Zeek:

.. literalinclude:: examples/my-http.evt
    :caption: my-http.evt
    :linenos:
    :language: spicy-evt

The first block (lines 1-3) tells Zeek that we have a new protocol
analyzer to provide. The analyzer's Zeek-side name is
``spicy::MyHTTP``, and it's meant to run on top of TCP connections
(line 1). Lines 2-3 then provide Zeek with more specifics: The entry
point for originator-side payload is the ``MyHTTP::RequestLine`` unit
type that our Spicy grammar defines (line 2); and we want Zeek to
activate our analyzer for all connections with a responder port of
12345 (which, of course, matches the packet trace we created).

The second block (line 5) tells Zeek that we want to
define one event. On the left-hand side of that line we give the unit
that is to trigger the event. The right-hand side defines its name and
arguments. What we are saying here is that every time a ``RequestLine``
line has been fully parsed, we'd like a ``MyHTTP::request_line`` event
to go to Zeek. Each event instance will come with four parameters:
Three of them are the values of corresponding unit fields, accessed
just through normal Spicy expressions (inside an event argument
expression, ``self`` refers to the unit instance that has led to the
generation of the current event). The first parameter, ``$conn``, is a
"magic" keyword that passes the Zeek-side
connection ID (``conn_id``) to the event.

Now we got everything in place that we need for our new protocol
analyzer---except for a Zeek script actually doing something with the
information we are parsing. Let's use this:

.. literalinclude:: examples/my-http.zeek
    :caption: my-http.zeek
    :language: zeek

You see an Zeek event handler for the event that we just defined,
having the expected signature of four parameters matching the types of
the parameter expressions that the ``*.evt`` file specifies. The
handler's body then just prints out what it gets.

.. _example_spicy_my_http:

Finally we can put together our pieces by compiling the Spicy grammar and the
EVT file into an HLTO file with ``spicyz``, and by pointing Zeek at the produced
file and the analyzer-specific Zeek scripts::

    # spicyz my-http.spicy my-http.evt -o my-http.hlto
    # zeek -Cr request-line.pcap my-http.hlto my-http.zeek
    Zeek saw from 127.0.0.1: GET /index.html 1.0

When Zeek starts up here the Spicy integration registers a protocol analyzer to
the entry point of our Spicy grammar as specified in the EVT file. It then
begins processing the packet trace as usual, now activating our new analyzer
whenever it sees a TCP connection on port 12345. Accordingly, the
``MyHTTP::request_line`` event gets generated once the parser gets to process
the session's payload. The Zeek event handler then executes and prints the
output we would expect.

.. note::

    By default, Zeek suppresses any output from Spicy-side
    ``print`` statements. You can add ``Spicy::enable_print=T`` to the
    command line to see it. In the example above, you would then get
    an additional line of output: ``GET, /index.html, 1.0``.

