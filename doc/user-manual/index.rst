
.. Bro User's Manual master file

===============
Bro User Manual
===============

.. toctree::
    :maxdepth: 2

    intro
    starting
    basics
    scripting
    io
    apps
    signatures
    broctl
    cluster
    summary

.. code:: bro

    print "foo!"

.. btest:: my-name

    @TEST-COPY-FILE: ${TRACES}/wikipedia.trace
    @TEST-EXEC: btest-rst-cmd echo doedelido
    @TEST-EXEC: btest-rst-cmd ls

