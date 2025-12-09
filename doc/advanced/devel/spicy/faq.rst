
===
FAQ
===

.. _faq_zeek_install_spicy_and_plugin_to_use_parsers:

.. rubric:: Do I need to install Spicy and/or a Zeek plugin to use Spicy parsers in Zeek?

If you're using Zeek >= 5.0 with a default build configuration,
there's nothing else you need to install. After installing Zeek, the
same folder containing the ``zeek`` binary will also have the relevant
Spicy tools, such as  ``spicyc`` (provided by Spicy) and ``spicyz``
(provided by Zeek). To double check that the Spicy support is indeed
available, look for ``Zeek::Spicy`` in the output of ``zeek -N``::

    # zeek -N
    <...>
    Zeek::Spicy - Support for Spicy parsers (``*.spicy``, ``*.evt``, ``*.hlto``) (built-in)

Note that it remains possible to build Zeek against an external Spicy
installation, or even without any Spicy support at all. Look at Zeek's
``configure`` for corresponding options.

.. note::

    For some historic background: Zeek 5.0 started bundling Spicy, as well
    as the former Zeek plugin for Spicy, so that now nothing else needs to
    be installed separately anymore to use Spicy parsers. Since Zeek 6.0,
    the code for that former plugin has further moved into Zeek itself,
    and is now maintained directly by the Zeek developers.


.. _faq_zeek_spicy_dpd_support:

.. rubric:: Does Spicy support *Dynamic Protocol Detection (DPD)*?

Yes, see the :ref:`corresponding section <spicy_dpd>` on how to add it
to your analyzers.

.. _faq_zeek_layer2_analyzer:

.. rubric:: Can I write a Layer 2 protocol analyzer with Spicy?

Yes, you can. In Zeek terminology a layer 2 protocol analyzer is a packet
analyzer, see the :ref:`corresponding section <spicy_packet_analyzer>` on how
to declare such an analyzer.

.. _faq_zeek_print_statements_no_effect:

.. rubric:: I have ``print`` statements in my Spicy grammar, why do I not see any output when running Zeek?

Zeek by default disables the output of Spicy-side ``print``
statements. To enable them, add ``Spicy::enable_print=T`` to the Zeek
command line (or ``redef Spicy::enable_print=T;`` to a Zeek script
that you are loading).

.. _faq_zeek_tcp_analyzer_not_all_messages_recognized:

.. rubric:: My analyzer recognizes only one or two TCP packets even though there are more in the input.

In Zeek, a Spicy analyzer parses the sending and receiving sides of a TCP
connection each according to the given Spicy grammar. This means that
if more than one message can be sent per side the grammar needs to
allow for that. For example, if the grammar parses messages of the
protocol as ``Message``, the top-level parsing unit given in the EVT
file needs to be able to parse a list of messages ``Message[]``.

One way to express this is to introduce a parser which wraps messages
of the protocol in an :spicylink:`anonymous field
<programming/parsing.html#anonymous-fields>`.

.. warning:: Since in general the number of messages exchanged over a TCP
  connection is unbounded, an anonymous field should be used. If a named field
  was used instead the parser would need to store all messages over the
  connection which would lead to unbounded memory growth.

.. code-block:: spicy

   type Message = unit {
     # Fields for messages of the protocol.
   };

   # Parser used e.g., in EVT file.
   public type Messages = unit {
     : Message[];
   };

