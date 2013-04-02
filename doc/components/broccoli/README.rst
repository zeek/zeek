..	-*- mode: rst-mode -*-
..
.. Version number is filled in automatically.
.. |version| replace:: 1.92-9

===============================================
Broccoli: The Bro Client Communications Library
===============================================

.. rst-class:: opening

  Broccoli is the "Bro client communications library". It allows you
  to create client sensors for the Bro intrusion detection system.
  Broccoli can speak a good subset of the Bro communication protocol,
  in particular, it can receive Bro IDs, send and receive Bro events,
  and send and receive event requests to/from peering Bros. You can
  currently create and receive values of pure types like integers,
  counters, timestamps, IP addresses, port numbers, booleans, and
  strings.


Download
--------

You can find the latest Broccoli release for download at
http://www.bro.org/download.

Broccoli's git repository is located at
`git://git.bro.org/broccoli <git://git.bro.org/broccoli>`_. You
can browse the repository `here <http://git.bro.org/broccoli>`_.

This document describes Broccoli |version|. See the ``CHANGES``
file for version history.


Installation
------------

The Broccoli library has been tested on Linux, the BSDs, and Solaris.
A Windows build has not currently been tried but is part of our future
plans. If you succeed in building Broccoli on other platforms, let us
know!


Prerequisites
-------------

Broccoli relies on the following libraries and tools, which need to be
installed before you begin:

    Flex (Fast Lexical Analyzer)
        Flex is already installed on most systems, so with luck you
        can skip having to install it yourself.

    Bison (GNU Parser Generator)
        This comes with many systems, but if you get errors compiling
        parse.y, you will need to install it.

    OpenSSL headers and libraries
        For encrypted communication. These are likely installed,
        though some platforms may require installation of a 'devel'
        package for the headers.

    CMake 2.6.3 or greater
        CMake is a cross-platform, open-source build system, typically
        not installed by default.  See http://www.cmake.org for more
        information regarding CMake and the installation steps below
        for how to use it to build this distribution.  CMake generates
        native Makefiles that depend on GNU Make by default.

Broccoli can also make use of some optional libraries if they are found at
installation time:

Libpcap headers and libraries
    Network traffic capture library


Installation
------------

To build and install into ``/usr/local``::

    ./configure
    make
    make install

This will perform an out-of-source build into the build directory using the
default build options and then install libraries into ``/usr/local/lib``.

You can specify a different installation directory with::

    ./configure --prefix=<dir>

Or control the python bindings install destination more precisely with::

    ./configure --python-install-dir=<dir>

Run ``./configure --help`` for more options.


Further notable configure options:

  ``--enable-debug``
      This one enables lots of debugging output. Be sure to disable
      this when using the library in a production environment! The
      output could easily end up in undersired places when the stdout
      of the program you've instrumented is used in other ways.

  ``--with-configfile=FILE``
      Broccoli can read key/value pairs from a config file. By default
      it is located in the etc directory of the installation root
      (exception: when using ``--prefix=/usr``, ``/etc`` is used
      instead of /usr/etc). The default config file name is
      broccoli.conf. Using ``--with-configfile``, you can override the
      location and name of the config file.

To use the library in other programs & configure scripts, use the
``broccoli-config`` script. It gives you the necessary configuration flags
and linker flags for your system, see ``--cflags`` and ``--libs``.

The API is contained in broccoli.h and pretty well documented. A few
usage examples can be found in the test directory, in particular, the
``broping`` tool can be used to test event transmission and reception. Have
a look at the policy file ``broping.bro`` for the events that need to be
defined at the peering Bro. Try ``broping -h`` for a look at the available
options.

Broccoli knows two kinds of version numbers: the release version number
(as in "broccoli-x.y.tar.gz", or as shipped with Bro) and the shared
library API version number (as in libbroccoli.so.3.0.0). The former
relates to changes in the tree, the latter to compatibility changes in
the API.

Comments, feedback and patches are appreciated; please check the `Bro
website <http://www.bro.org/community>`_.

Documentation
-------------

Please see the `Broccoli User Manual <./broccoli-manual.html>`_ and
the `Broccoli API Reference <../../broccoli-api/index.html>`_.
