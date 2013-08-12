
.. Bro documentation master file

=================
Bro Documentation
=================

Guides
------

.. toctree::
   :maxdepth: 1

   INSTALL
   upgrade
   quickstart
   faq
   reporting-problems

Frameworks
----------

.. toctree::
   :maxdepth: 1

   notice
   logging
   input
   file-analysis
   cluster
   signatures

How-Tos
-------

.. toctree::
   :maxdepth: 2

   intro/index.rst
   using/index.rst
   scripting/index.rst
   frameworks/index.rst
   cluster/index.rst
   scripts/index.rst
   misc/index.rst
   components/index.rst
   indices/index.rst

Just Testing
============

.. code:: bro

   scripts/packages
   scripts/index
   scripts/builtins
   scripts/proto-analyzers
   scripts/file-analyzers

.. btest:: test

    @TEST-COPY-FILE: ${TRACES}/wikipedia.trace
    @TEST-EXEC: btest-rst-cmd bro -r wikipedia.trace 
    @TEST-EXEC: btest-rst-cmd "cat http.log | bro-cut ts id.orig_h | head -5"

Test part 1 coming up.

.. btest:: test-parts

    @TEST-EXEC: echo It works! >output

Something else here.

.. btest:: test-parts

    @TEST-EXEC: btest-rst-include output

