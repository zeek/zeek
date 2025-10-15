
.. _spicy_tutorial:

Tutorial
========

This tutorial walks through the integration of a simple TFTP analyzer
into Zeek. This discussion continues  the example from
:spicylink:`Spicy's own tutorial <tutorial/index.html>` that develops
the TFTP grammar, now focusing on how to use it with Zeek. Please go
through that Spicy tutorial first before continuing here.

To turn a Spicy-side grammar into a Zeek analyzer, we need to provide
Zeek with a description of how to employ it. There are two parts to
that: Telling Zeek when to activate the analyzer, and defining events
to generate. In addition, we will need a Zeek-side script to do
something with our new TFTP events. We will walk through this in the
following, starting with the mechanics of compiling the Spicy analyzer
for Zeek. While we will build up the files involved individually
first, see the :ref:`final section <zkg_create_package>` for how the
Zeek package manager, *zkg*, can be used to bootstrap a new Zeek
package with a skeleton of everything needed for an analyzer.

Before proceeding, make sure that your Zeek comes with Spicy support
built-in---which is the default since Zeek version 5.0::

    # zeek - N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (built-in)

You should also have ``spicyz`` in your ``PATH``::

    # which spicyz
    /usr/local/zeek/bin/spicyz

.. note::

    There are a number of pieces involved in creating a full Zeek
    analyzer, in particular if you want to distribute it as a Zeek
    package. To help you get started with that, Zeek's package manager
    can create a skeleton Spicy package by running::

        # zkg create --features=spicy-protocol-analyzer --packagedir <packagedir>

    The generated files mark places that will need manual editing with
    ``TODO``. See the :ref:`tutorial <zkg_create_package>` for more on
    this.

Compiling the Analyzer
----------------------

Zeek comes with a tool :ref:`spicyz <spicyz>` that compiles Spicy
analyzers into binary code that Zeek can load through a Spicy plugin.
The following command line produces a binary object file ``tftp.hlto``
containing the executable analyzer code:

.. code::

    # spicyz -o tftp.hlto tftp.spicy

Below, we will prepare an additional interface definition file
``tftp.evt`` that describes the analyzer's integration into Zeek. We
will need to give that to ``spicyz`` as well, and our full
compilation command hence becomes:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt

When starting Zeek, we add ``tftp.hlto`` to its command line:

.. code::

    # zeek -r tftp_rrq.pcap tftp.hlto


Activating the Analyzer
-----------------------

In *Getting Started*, :ref:`we already saw
<example_spicy_my_http_adding_analyzer>` how to inform Zeek about a new
protocol analyzer. We follow the same scheme here and put the
following into ``tftp.evt``, the analyzer definition file:

.. literalinclude:: autogen/tftp.evt
    :lines: 3-5
    :language: spicy-evt

The first line provides our analyzer with a Zeek-side name
(``spicy::TFTP``) and also tells Zeek that we are adding an
application analyzer on top of UDP (``over UDP``). ``TFTP::Packet``
provides the top-level entry point for parsing both sides of a TFTP
connection. Furthermore, we want Zeek to automatically activate our
analyzer for all sessions on UDP port 69 (i.e., TFTP's well known
port). See :ref:`spicy_evt_analyzer_setup` for more details on defining
such a ``protocol analyzer`` section.

.. note::

    We use the ``port`` attribute in the ``protocol analyzer`` section
    mainly for convenience; it's not the only way to define the
    well-known ports. For a production analyzer, it's more idiomatic
    to use the a Zeek script instead; see :ref:`this note
    <zeek_init_instead_of_port>` for more information.

With this in place, we can already employ the analyzer inside Zeek. It
will not generate any events yet, but we can at least see the output of
the ``on %done { print self; }`` hook that still remains part of the
grammar from earlier:

.. code::

    # zeek -r tftp_rrq.pcap tftp.hlto Spicy::enable_print=T
    [$opcode=Opcode::RRQ, $rrq=[$filename=b"rfc1350.txt", $mode=b"octet"], $wrq=(not set), $data=(not set), $ack=(not set), $error=(not set)]

As by default, the Zeek plugin does not show the output of Spicy-side
``print`` statements, we added ``Spicy::enable_print=T`` to the
command line to turn that on. We see that Zeek took care of the
lower network layers, extracted the UDP payload from the Read Request,
and passed that into our Spicy parser. (If you want to view more about
the internals of what is happening here, there are a couple kinds of
:ref:`debug output available <spicy_debugging>`.)

You might be wondering why there is only one line of output, even
though there are multiple TFTP packets in our pcap trace. Shouldn't
the ``print`` execute multiple times? Yes, it should, but it does not
currently: Due to some intricacies of the TFTP protocol, our analyzer
gets to see only the first packet for now. We will fix this later. For
now, we focus on the Read Request packet that the output above shows.

Defining Events
---------------

The core task of any Zeek analyzer is to generate events for Zeek
scripts to process. For binary protocols, events will often correspond
pretty directly to data units specified by their specifications---and
TFTP is no exception. We start with an event for Read/Write Requests
by adding this definition to ``tftp.evt``:

.. literalinclude:: examples/tftp-single-request.evt
    :lines: 5-7
    :language: spicy-evt

The first line makes our Spicy TFTP grammar available to the rest of
the file. The line ``on ...`` defines one event: Every time a
``Request`` unit will be parsed, we want to receive an event
``tftp::request`` with one parameter: the connection it belongs to.
Here, ``$conn`` is a reserved identifier that will turn into the
standard `connection record
<https://docs.zeek.org/en/current/scripts/base/init-bare.zeek.html#type-connection>`_
record on the Zeek side.

Now we need a Zeek event handler for our new event. Let's put this
into ``tftp.zeek``:

.. literalinclude:: examples/tftp-single-request.zeek
    :language: zeek

Running Zeek then gives us:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp]

Let's extend the event signature a bit by passing further arguments:

.. literalinclude:: examples/tftp-single-request-more-args.evt
    :lines: 5-7
    :language: spicy-evt

This shows how each parameter gets specified as a Spicy expression:
``self`` refers to the instance currently being parsed (``self``), and
``self.filename`` retrieves the value of its ``filename`` field.
``$is_orig`` is another reserved ID that turns into a boolean that
will be true if the event has been triggered by originator-side
traffic. On the Zeek side, our event now has the following signature:

.. literalinclude:: examples/tftp-single-request-more-args.zeek
    :language: zeek

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], T, rfc1350.txt, octet

Going back to our earlier discussion of Read vs Write Requests, we do
not yet make that distinction with the ``request`` event that we are
sending to Zeek-land. However, since we had introduced the ``is_read``
unit parameter, we can easily separate the two by gating event
generation through an additional ``if`` condition:

.. literalinclude:: autogen/tftp.evt
    :lines: 9-10
    :language: spicy-evt

This now defines two separate events, each being generated only for
the corresponding value of ``is_read``. Let's try it with a new
``tftp.zeek``:

.. literalinclude:: examples/tftp-two-requests.zeek
    :language: zeek

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP read request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], T, rfc1350.txt, octet

If we look at the ``conn.log`` that Zeek produces during this run, we
will see that the ``service`` field is not filled in yet. That's
because our analyzer does not yet confirm to Zeek that it has been
successful in parsing the content. To do that, we can call a library
function that Spicy makes available once we have successfully parsed a
request: :spicylink:`spicy::accept_input
<programming/library.html#spicy-accept-input>`. That function signals
the host application---i.e., Zeek in our case—--that the parser is
processing the expected protocol. With that, our request looks like
this now:

.. code-block::

    type Request = unit(is_read: bool) {
        filename: bytes &until=b"\x00";
        mode:     bytes &until=b"\x00";

        on %done { spicy::accept_input(); }
    };


Let's try it again:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP read request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], T, rfc1350.txt, octet
    # cat conn.log
    [...]
    1367411051.972852  C1f7uj4uuv6zu2aKti  192.168.0.253  50618  192.168.0.10  69  udp  spicy_tftp  -  -  -  S0  -  -0  D  1  48  0  0  -
    [...]

Now the service field says TFTP! (There will be a 2nd connection in
the log that we are not showing here; see the next section on that).

Turning to the other TFTP packet types, it is straight-forward to add
events for them as well. The following is our complete ``tftp.evt``
file:

.. literalinclude:: autogen/tftp.evt
    :lines: 3-
    :language: spicy-evt



Detour: Zeek vs. TFTP
---------------------

We noticed above that Zeek seems to be seeing only a single TFTP
packet from our input trace, even though ``tcpdump`` shows that the
pcap file contains multiple different types of packets. The reason
becomes clear once we look more closely at the UDP ports that are in
use:

.. code::

    # tcpdump -ttnr tftp_rrq.pcap
    1367411051.972852 IP 192.168.0.253.50618 > 192.168.0.10.69:  20 RRQ "rfc1350.txtoctet" [tftp]
    1367411052.077243 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    1367411052.081790 IP 192.168.0.253.50618 > 192.168.0.10.3445: UDP, length 4
    1367411052.086300 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    1367411052.088961 IP 192.168.0.253.50618 > 192.168.0.10.3445: UDP, length 4
    1367411052.088995 IP 192.168.0.10.3445 > 192.168.0.253.50618: UDP, length 516
    [...]

Turns out that only the first packet is using the well-known TFTP port
69/udp, whereas all the subsequent packets use ephemeral ports. Due to
the port difference, Zeek believes it is seeing two independent
network connections, and it does not associate TFTP with the second
one at all due to its lack of the well-known port (neither does
``tcpdump``!). Zeek's connection log confirms this by showing two
separate entries:

.. code::

    # cat conn.log
    1367411051.972852  CH3xFz3U1nYI1Dp1Dk  192.168.0.253  50618  192.168.0.10  69  udp  spicy_tftp  -  -  -  S0  -  -  0  D  1  48  0  0  -
    1367411052.077243  CfwsLw2TaTIeo3gE9g  192.168.0.10  3445  192.168.0.253  50618  udp  -  0.181558  24795  196  SF  -  -  0  Dd  49  26167  49  1568  -

Switching the ports for subsequent packets is a quirk in TFTP that
resembles similar behaviour in standard FTP, where data connections
get set up separately as well. Fortunately, Zeek provides a built-in
function to designate a specific analyzer for an anticipated future
connection. We can call that function when we see the initial request:

.. literalinclude:: examples/tftp-schedule-analyzer.zeek
    :language: zeek

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    TFTP read request, [orig_h=192.168.0.253, orig_p=50618/udp, resp_h=192.168.0.10, resp_p=69/udp], rfc1350.txt, octet
    TFTP data, 1, \x0a\x0a\x0a\x0a\x0a\x0aNetwork Working Group [...]
    TFTP ack, 1
    TFTP data, 2, B Official Protocol\x0a   Standards" for the  [...]
    TFTP ack, 2
    TFTP data, 3, protocol was originally designed by Noel Chia [...]
    TFTP ack, 3
    TFTP data, 4, r mechanism was suggested by\x0a   PARC's EFT [...]
    TFTP ack, 4
    [...]

Now we are seeing all the packets as we would expect.


Zeek Script
-----------

Analyzers normally come along with a Zeek-side script that implements
a set of standard base functionality, such as recording activity into
a protocol specific log file. These scripts provide handlers for the
analyzers' events, and collect and correlate their activity as
desired. We have created such :download:`a script for TFTP
<autogen/tftp.zeek>`, based on the events that our Spicy analyzer
generates. Once we add that to the Zeek command line, we will see a
new ``tftp.log``:

.. code::

    # spicyz -o tftp.hlto tftp.spicy tftp.evt
    # zeek -r tftp_rrq.pcap tftp.hlto tftp.zeek
    # cat tftp.log
    #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	wrq	fname	mode	uid_data	size	block_sent	block_acked	error_code	error_msg
    1367411051.972852	CKWH8L3AIekSHYzBU	192.168.0.253	50618	192.168.0.10	69	F	rfc1350.txt	octet	ClAr3P158Ei77Fql8h	24599	49	49	-	-

The TFTP script also labels the second session as TFTP data by
adding a corresponding entry to the ``service`` field inside the
Zeek-side connection record. With that, we are now seeing this in
``conn.log``:

.. code::

    1367411051.972852  ChbSfq3QWKuNirt9Uh  192.168.0.253  50618  192.168.0.10  69  udp  spicy_tftp  -  -  -  S0  -  -0  D  1  48  0  0  -
    1367411052.077243  CowFQj20FHHduhHSYk  192.168.0.10  3445  192.168.0.253  50618  udp  spicy_tftp_data  0.181558  24795  196  SF  --  0  Dd  49  26167  49  1568  -

The TFTP script ends up being a bit more complex than one would expect
for such a simple protocol. That's because it tracks the two related
connections (initial request and follow-up traffic on a different
port), and combines them into a single TFTP transaction for logging.
Since there is nothing Spicy-specific in that Zeek script, we skip
discussing it here in more detail.


.. _zkg_create_package:

Creating a Zeek Package
-----------------------

We have now assembled all the parts needed for providing a new
analyzer to Zeek. By adding a few further pieces, we can wrap that
analyzer into a full *Zeek package* for others to install easily
through *zkg*. To help create that wrapping, *zkg* provides a template
for instantiating a skeleton analyzer package as a starting point. The
skeleton comes in three different flavors, depending on which kind of
analyzer you want to create: protocol, file, or packet analyzer.
In each case, it creates all the necessary files along with the
appropriate directory layout, and even includes a couple of
standard test cases.

To create the scaffolding for our TFTP analyzer, execute the following
command and provide the requested information::

    # zkg create --features spicy-protocol-analyzer --packagedir spicy-tftp
    "package-template" requires a "name" value (the name of the package, e.g. "FooBar" or "spicy-http"):
    name: spicy-tftp
    "package-template" requires a "analyzer" value (name of the Spicy analyzer, which typically corresponds to the protocol/format being parsed (e.g. "HTTP", "PNG")):
    analyzer: TFTP
    "package-template" requires a "protocol" value (transport protocol for the analyzer to use: TCP or UDP):
    protocol: UDP
    "package-template" requires a "unit_orig" value (name of the top-level Spicy parsing unit for the originator side of the connection (e.g. "Request")):
    unit_orig: Packet
    "package-template" requires a "unit_resp" value (name of the top-level Spicy parsing unit for the responder side of the connection (e.g. "Reply"); may be the same as originator side):
    unit_resp: Packet


The above creates the following files (skipping anything related to
``.git``)::

    spicy-tftp/CMakeLists.txt
    spicy-tftp/COPYING
    spicy-tftp/README
    spicy-tftp/analyzer/CMakeLists.txt
    spicy-tftp/analyzer/tftp.evt
    spicy-tftp/analyzer/tftp.spicy
    spicy-tftp/cmake/FindSpicyPlugin.cmake
    spicy-tftp/scripts/__load__.zeek
    spicy-tftp/scripts/dpd.sig
    spicy-tftp/scripts/main.zeek
    spicy-tftp/testing/Baseline/tests.run-pcap/conn.log
    spicy-tftp/testing/Baseline/tests.run-pcap/output
    spicy-tftp/testing/Baseline/tests.standalone/
    spicy-tftp/testing/Baseline/tests.standalone/output
    spicy-tftp/testing/Baseline/tests.trace/output
    spicy-tftp/testing/Baseline/tests.trace/tftp.log
    spicy-tftp/testing/Files/random.seed
    spicy-tftp/testing/Makefile
    spicy-tftp/testing/Scripts/README
    spicy-tftp/testing/Scripts/diff-remove-timestamps
    spicy-tftp/testing/Scripts/get-zeek-env
    spicy-tftp/testing/Traces/tcp-port-12345.pcap
    spicy-tftp/testing/Traces/udp-port-12345.pcap
    spicy-tftp/testing/btest.cfg
    spicy-tftp/testing/tests/availability.zeek
    spicy-tftp/testing/tests/standalone.spicy
    spicy-tftp/testing/tests/trace.zeek
    spicy-tftp/zkg.meta


Note the ``*.evt``, ``*.spicy``, ``*.zeek`` files: they correspond to
the files we created for TFTP in the preceding sections; we can just
move our versions in there. Furthermore, the generated scaffolding
marks places with ``TODO`` that need manual editing: use ``git grep
TODO`` inside the ``spicy-tftp`` directory to find them. We won't go
through all the specific customizations for TFTP here, but for
reference you can find the full TFTP package as created from the *zkg*
template on `GitHub <https://github.com/zeek/spicy-tftp>`_.

If instead of a protocol analyzer, you'd like to create a file or
packet analyzer, run zkg with ``--features spicy-file-analyzer`` or
``--features spicy-packet-analyzer``, respectively. The generated
skeleton will be suitably adjusted then.
