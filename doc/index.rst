
.. Bro documentation master file

=================
Bro Documentation
=================

.. toctree::
    :maxdepth: 2
    :numbered:

    user-manual/index
    reference/index

Just Testing
============

.. code:: bro

    print "Hey Bro!"

.. btest:: test

    @TEST-COPY-FILE: ${TRACES}/wikipedia.trace
    @TEST-EXEC: btest-rst-cmd bro -r wikipedia.trace 
    @TEST-EXEC: btest-rst-cmd "cat http.log | bro-cut ts id.orig_h | head -5"

