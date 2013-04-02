..	-*- mode: rst-mode -*-
..
.. Version number is filled in automatically.
.. |version| replace:: 0.34-3

======
BinPAC
======

.. rst-class:: opening

    BinPAC is a high level language for describing protocol parsers and
    generates C++ code.  It is currently maintained and distributed with the
    Bro Network Security Monitor distribution, however, the generated parsers
    may be used with other programs besides Bro.

Download
--------

You can find the latest BinPAC release for download at
http://www.bro.org/download.

BinPAC's git repository is located at `git://git.bro.org/binpac.git
<git://git.bro.org/binpac.git>`__. You can browse the repository
`here <http://git.bro.org/binpac.git>`__.

This document describes BinPAC |version|. See the ``CHANGES``
file for version history.

Prerequisites
-------------

BinPAC relies on the following libraries and tools, which need to be
installed before you begin:

    * Flex (Fast Lexical Analyzer)
       Flex is already installed on most systems, so with luck you can
       skip having to install it yourself.

    * Bison (GNU Parser Generator)
       Bison is also already installed on many system.

    * CMake 2.6.3 or greater
       CMake is a cross-platform, open-source build system, typically
       not installed by default.  See http://www.cmake.org for more
       information regarding CMake and the installation steps below for
       how to use it to build this distribution.  CMake generates native
       Makefiles that depend on GNU Make by default

Installation
------------

To build and install into ``/usr/local``::

    ./configure
    cd build
    make
    make install

This will perform an out-of-source build into the build directory using
the default build options and then install the binpac binary into
``/usr/local/bin``.

You can specify a different installation directory with::

   ./configure --prefix=<dir>

Run ``./configure --help`` for more options.
