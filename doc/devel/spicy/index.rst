============================
Writing Analyzers with Spicy
============================

:spicylink:`Spicy <index.html>` is a parser generator that makes it
easy to create robust C++ parsers for network protocols, file formats,
and more. Zeek supports integrating Spicy analyzers so that one can
create Zeek protocol, packet and file analyzers. This section digs
into how that integration works. We begin with a short "Getting
Started" guide showing you the basics of using Spicy with Zeek,
followed by an in-depth tutorial on adding a complete protocol
analyzer to Zeek. The final part consists of a reference section
documenting everything the Spicy integration supports.

While this documentation walks through all the bits and pieces that an
analyzer consists of, there's an easy way to get started when writing
a new analyzer from scratch: the `Zeek package manager
<https://docs.zeek.org/projects/package-manager>`_ can create analyzer
scaffolding for you that includes an initial Spicy grammar
(``*.spicy``), Zeek integration glue code (``*.evt``; see below) and a
corresponding CMake build setup. To create that scaffolding, use the
package managers ``create`` command and pass one of
``--features=spicy-protocol-analyzer``,
``--features=spicy-packet-analyzer``, or
``--features=spicy-file-analyzer`` to create a Zeek protocol, packet,
or file analyzer, respectively. See :ref:`the tutorial
<zkg_create_package>` for more on this.

Note that Zeek itself installs the grammars of its builtin Spicy
analyzers for potential reuse. For example, the `Finger grammar
<https://github.com/zeek/zeek/blob/master/src/analyzer/protocol/finger/finger.spicy>`_
gets installed to ``<PREFIX>/share/spicy/finger/finger.spicy``. It can
be used in custom code by importing it with ``import Finger from
finger;``.

.. toctree::
   :maxdepth: 2
   :caption: Table of Contents

   installation
   getting-started
   tutorial
   reference
   faq

.. note::

   This documentation focuses on writing *external* Spicy analyzers
   that you can load into Zeek at startup. Zeek also comes with the
   infrastructure to build Spicy analyzers directly into the
   executable itself, just like traditional built-in analyzers. We
   will document this more as we're converting more of Zeek's built-in
   analyzers over to Spicy. For now, we recommend locking at one of
   the existing built-in Spicy analyzers (Syslog, Finger) as examples.

.. _spicy_terminology:

Terminology
===========

A word on terminology: In Zeek, the term "analyzer" generally refers
to a component that processes a particular protocol ("protocol
analyzer"), file format ("file analyzer"), or low-level packet
structure ("packet analyzer"). "Processing" here means more than just
parsing content: An analyzer controls when it wants to be used (e.g.,
with connections on specific ports, or with files of a specific MIME
type); what events to generate for Zeek's scripting layer; and how to
handle any errors occurring during parsing. While Spicy itself focuses
just on the parsing part, Spicy makes it possible to provide the
remaining pieces to Zeek, turning a Spicy parser into a full Zeek
analyzer. That's what we refer to as a "Spicy (protocol/file/packet)
analyzer" for Zeek.

