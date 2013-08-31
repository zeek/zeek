..	-*- mode: rst-mode -*-
..
.. Version number is filled in automatically.
.. |version| replace:: 0.54

============================
Python Bindings for Broccoli
============================

.. rst-class:: opening

    This Python module provides bindings for Broccoli, Bro's client
    communication library. In general, the bindings provide the same
    functionality as Broccoli's C API.

.. contents::


Download
--------

You can find the latest Broccoli-Python release for download at
http://www.bro.org/download.

Broccoli-Python's git repository is located at `git://git.bro.org/broccoli-python.git
<git://git.bro.org/broccoli-python.git>`__. You can browse the repository
`here <http://git.bro.org/broccoli-python.git>`__.

This document describes Broccoli-Python |version|. See the ``CHANGES``
file for version history.


Installation
------------

Installation of the Python module is pretty straight-forward. After
Broccoli itself has been installed, it follows the standard installation
process for Python modules::

    python setup.py install

Try the following to test the installation. If you do not see any
error message, everything should be fine::

    python -c "import broccoli"

Usage
-----

The following examples demonstrate how to send and receive Bro
events in Python.

The main challenge when using Broccoli from Python is dealing with
the data types of Bro event parameters as there is no one-to-one
mapping between Bro's types and Python's types. The Python modules
automatically maps between those types which both systems provide
(such as strings) and provides a set of wrapper classes for Bro
types which do not have a direct Python equivalent (such as IP
addresses).

Connecting to Bro
~~~~~~~~~~~~~~~~~

The following code sets up a connection from Python to a remote Bro
instance (or another Broccoli) and provides a connection handle for
further communication::

     from broccoli import *
     bc = Connection("127.0.0.1:47758")

An ``IOError`` will be raised if the connection cannot be established.

Sending Events
~~~~~~~~~~~~~~

Once you have a connection handle ``bc`` set up as shown above, you can
start sending events::

     bc.send("foo", 5, "attack!")

This sends an event called ``foo`` with two parameters, ``5`` and
``attack!``. Broccoli operates asynchronously, i.e., events scheduled
with ``send()`` are not always sent out immediately but might be
queued for later transmission. To ensure that all events get out
(and incoming events are processed, see below), you need to call
``bc.processInput()`` regularly.

Data Types
~~~~~~~~~~

In the example above, the types of the event parameters are
automatically derived from the corresponding Python types: the first
parameter (``5``) has the Bro type ``int`` and the second one
(``attack!``) has Bro type ``string``.

For types which do not have a Python equivalent, the ``broccoli``
module provides wrapper classes which have the same names as the
corresponding Bro types. For example, to send an event called ``bar``
with one ``addr`` argument and one ``count`` argument, you can write::

     bc.send("bar", addr("192.168.1.1"), count(42))

The following table summarizes the available atomic types and their
usage.

========   ===========   ===========================
Bro Type   Python Type   Example
========   ===========   ===========================
addr                     ``addr("192.168.1.1")``
bool       bool          ``True``
count                    ``count(42)``
double     float         ``3.14``
enum                     Type currently not supported
int 	   int           ``5``
interval                 ``interval(60)``
net                      Type currently not supported
port	                 ``port("80/tcp")``
string     string        ``"attack!"``
subnet                   ``subnet("192.168.1.0/24")``
time                     ``time(1111111111.0)``
========   ===========   ===========================

The ``broccoli`` module also supports sending Bro records as event
parameters. To send a record, you first define a record type. For
example, a Bro record type::

    type my_record: record {
        a: int;
        b: addr;
        c: subnet;
    };

turns into Python as::

    my_record = record_type("a", "b", "c")

As the example shows, Python only needs to know the attribute names
but not their types. The types are derived automatically in the same
way as discussed above for atomic event parameters.

Now you can instantiate a record instance of the newly defined type
and send it out::

    rec = record(my_record)
    rec.a = 5
    rec.b = addr("192.168.1.1")
    rec.c = subnet("192.168.1.0/24")
    bc.send("my_event", rec)

.. note:: The Python module does not support nested records at this time.

Receiving Events
~~~~~~~~~~~~~~~~

To receive events, you define a callback function having the same
name as the event and mark it with the ``event`` decorator::

   @event
   def foo(arg1, arg2):
       print arg1, arg2

Once you start calling ``bc.processInput()`` regularly (see above),
each received ``foo`` event will trigger the callback function.

By default, the event's arguments are always passed in with built-in
Python types. For Bro types which do not have a direct Python
equivalent (see table above), a substitute built-in type is used
which corresponds to the type the wrapper class' constructor expects
(see the examples in the table). For example, Bro type ``addr`` is
passed in as a string and Bro type ``time`` is passed in as a float.

Alternatively, you can define a _typed_ prototype for the event. If you
do so, arguments will first be type-checked and then passed to the
call-back with the specified type (which means instances of the
wrapper classes for non-Python types). Example::

   @event(count, addr)
   def bar(arg1, arg2):
       print arg1, arg2

Here, ``arg1`` will be an instance of the ``count`` wrapper class and
``arg2`` will be an instance of the ``addr`` wrapper class.

Protoyping works similarly with built-in Python types::

   @event(int, string):
   def foo(arg1, arg2):
       print arg1, arg2

In general, the prototype specifies the types in which the callback
wants to receive the arguments. This actually provides support for
simple type casts as some types support conversion to into something
different. If for instance the event source sends an event with a
single port argument, ``@event(port)`` will pass the port as an
instance of the ``port`` wrapper class; ``@event(string)`` will pass it
as a string (e.g., ``"80/tcp"``); and ``@event(int)`` will pass it as an
integer without protocol information (e.g., just ``80``). If an
argument cannot be converted into the specified type, a ``TypeError``
will be raised.

To receive an event with a record parameter, the record type first
needs to be defined, as described above. Then the type can be used
with the ``@event`` decorator in the same way as atomic types::

   my_record = record_type("a", "b", "c")
   @event(my_record)
   def my_event(rec):
       print rec.a, rec.b, rec.c

Helper Functions
----------------

The ``broccoli`` module provides one helper function: ``current_time()``
returns the current time as a float which, if necessary, can be
wrapped into a ``time`` parameter (i.e., ``time(current_time()``)

Examples
--------

There are some example scripts in the ``tests/`` subdirectory of the
``broccoli-python`` repository
`here <http://git.bro.org/broccoli-python.git/tree/HEAD:/tests>`_:

   - ``broping.py`` is a (simplified) Python version of Broccoli's test program
     ``broping``. Start Bro with ``broping.bro``.

   - ``broping-record.py`` is a Python version of Broccoli's ``broping``
     for records. Start Bro with ``broping-record.bro``.

   - ``test.py`` is a very ugly but comprehensive regression test and part of
     the communication test-suite. Start Bro with ``test.bro``.
