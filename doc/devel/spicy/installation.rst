
.. _spicy_installation:

Installation
============

Since Zeek version 5.0, support for Spicy is built right into Zeek by
default. To confirm that Spicy is indeed available, you can inspect
the output of ``zeek -N``::

    # zeek -N Zeek::Spicy
    Zeek::Spicy - Support for Spicy parsers (*.hlto) (built-in)

It remains possible to build Zeek against an external Spicy
installation through Zeek's ``configure`` option
``--with-spicy=PATH``, where ``PATH`` points to the Spicy installation
directory. In that case, you also need to ensure that the Spicy tools
(e.g., ``spicyc``, ``spicy-config``) are available in ``PATH``.
