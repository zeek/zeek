
.. Bro documentation master file

=================
Bro Documentation
=================

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

    print "Hey Bro!"

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

