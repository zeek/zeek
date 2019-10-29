.. _CMake: http://www.cmake.org
.. _SWIG: http://www.swig.org
.. _Xcode: https://developer.apple.com/xcode/
.. _MacPorts: http://www.macports.org
.. _Fink: http://www.finkproject.org
.. _Homebrew: http://brew.sh
.. _downloads page: https://www.zeek.org/download/index.html
.. _devtoolset: https://developers.redhat.com/products/developertoolset/hello-world

.. _installing-zeek:

==========
Installing
==========

Prerequisites
=============

Before installing Zeek, you'll need to ensure that some dependencies
are in place.

Required Dependencies
---------------------

Zeek requires the following libraries and tools to be installed
before you begin:

    * Libpcap                           (http://www.tcpdump.org)
    * OpenSSL libraries                 (http://www.openssl.org)
    * BIND8 library
    * Libz
    * Bash (for ZeekControl)
    * Python 2.6 or greater (for ZeekControl)

To build Zeek from source, the following additional dependencies are required:

    * CMake 3.0 or greater              (http://www.cmake.org)
    * Make
    * C/C++ compiler with C++17 support (GCC 7+ or Clang 4+)
    * SWIG                              (http://www.swig.org)
    * Bison 2.5 or greater              (https://www.gnu.org/software/bison/)
    * Flex (lexical analyzer generator) (https://github.com/westes/flex)
    * Libpcap headers                   (http://www.tcpdump.org)
    * OpenSSL headers                   (http://www.openssl.org)
    * zlib headers                      (https://zlib.net/)
    * Python                            (https://www.python.org/)

To install the required dependencies, you can use:

* RPM/RedHat-based Linux:

  .. sourcecode:: console

     sudo yum install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python-devel swig zlib-devel

  On RHEL/CentOS 6/7, you can install and activate a devtoolset_ to get access
  to recent GCC versions. You will also have to install and activate CMake 3.
  For example:

  .. sourcecode:: console

     sudo yum install cmake3 devtoolset-7
     scl enable devtoolset-7 bash

* DEB/Debian-based Linux:

  .. sourcecode:: console

     sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev

  If your system uses Python 2.7, then you will also need to install the
  "python-ipaddress" package. If you are running Debian 8 (jessie), install
  clang-4.0 instead of GCC.

* FreeBSD:

  Most required dependencies should come with a minimal FreeBSD install
  except for the following.

  .. sourcecode:: console

      sudo pkg install bash cmake swig30 bison python py27-sqlite3 py27-ipaddress

* Mac OS X:

  Compiling source code on Macs requires first installing either Xcode_
  or the "Command Line Tools" (which is a much smaller download).  To check
  if either is installed, run the ``xcode-select -p`` command.  If you see
  an error message, then neither is installed and you can then run
  ``xcode-select --install`` which will prompt you to either get Xcode (by
  clicking "Get Xcode") or to install the command line tools (by
  clicking "Install").

  OS X comes with all required dependencies except for CMake_, SWIG_,
  Bison, and OpenSSL (OpenSSL headers were removed in OS X 10.11,
  therefore OpenSSL must be installed manually for OS X versions 10.11
  or newer).

  Distributions of these dependencies can likely be obtained from your
  preferred Mac OS X package management system (e.g. Homebrew_,
  MacPorts_, or Fink_). Specifically for Homebrew, the ``cmake``,
  ``swig``, ``openssl``, and ``bison`` packages
  provide the required dependencies.  For MacPorts, the ``cmake``,
  ``swig``, ``swig-python``, ``openssl``, and ``bison`` packages provide
  the required dependencies.


Optional Dependencies
---------------------

Zeek can make use of some optional libraries and tools if they are found at
build time:

    * libmaxminddb (for geolocating IP addresses)
    * sendmail (enables Zeek and ZeekControl to send mail)
    * curl (used by a Zeek script that implements active HTTP)
    * gperftools (tcmalloc is used to improve memory and CPU usage)
    * jemalloc (http://www.canonware.com/jemalloc/)
    * PF_RING (Linux only, see :doc:`Cluster Configuration <../configuration/index>`)
    * krb5 libraries and headers
    * ipsumdump (for trace-summary; http://www.cs.ucla.edu/~kohler/ipsumdump)

Geolocation is probably the most interesting and can be installed
on most platforms by following the instructions for :ref:`installing
the GeoIP library and database
<geolocation>`.


Installing Zeek
===============

Zeek can be downloaded in either pre-built binary package or source
code forms.


Using Pre-Built Binary Release Packages
---------------------------------------

See the `downloads page`_ for currently supported/targeted
platforms for binary releases and for installation instructions.

* Linux Packages

  Linux based binary installations are usually performed by adding
  information about the Zeek packages to the respective system packaging
  tool. Then the usual system utilities such as ``apt``, ``dnf``, ``yum``,
  or ``zypper`` are used to perform the installation.

The primary install prefix for binary packages is either ``/opt/bro``
or ``/opt/zeek`` (depending on which version you're using).

Installing from Source
----------------------

Zeek releases are bundled into source packages for convenience and are
available on the `downloads page`_.

Alternatively, the latest Zeek development version
can be obtained through git repositories
hosted at https://github.com/zeek.  See our `git development documentation
<https://www.zeek.org/development/howtos/process.html>`_ for comprehensive
information on Zeek's use of git revision control, but the short story
for downloading the full source code experience for Zeek via git is:

.. sourcecode:: console

    git clone --recursive https://github.com/zeek/zeek

.. note:: If you choose to clone the ``zeek`` repository
   non-recursively for a "minimal Zeek experience", be aware that
   compiling it depends on several of the other submodules as well.

The typical way to build and install from source is (for more options,
run ``./configure --help``):

.. sourcecode:: console

    ./configure
    make
    make install

If the ``configure`` script fails, then it is most likely because it either
couldn't find a required dependency or it couldn't find a sufficiently new
version of a dependency.  Assuming that you already installed all required
dependencies, then you may need to use one of the ``--with-*`` options
that can be given to the ``configure`` script to help it locate a dependency.

The default installation path is ``/usr/local/zeek``, which would typically
require root privileges when doing the ``make install``.  A different
installation path can be chosen by specifying the ``configure`` script
``--prefix`` option.  Note that ``/usr``, ``/opt/bro/``, and ``/opt/zeek`` are
the standard prefixes for binary Zeek packages to be installed, so those are
typically not good choices unless you are creating such a package.

OpenBSD users, please see our `FAQ
<https://www.zeek.org/documentation/faq.html>`_ if you are having
problems installing Zeek.

Depending on the Zeek package you downloaded, there may be auxiliary
tools and libraries available in the ``aux/`` directory. Some of them
will be automatically built and installed along with Zeek. There are
``--disable-*`` options that can be given to the configure script to
turn off unwanted auxiliary projects that would otherwise be installed
automatically.  Finally, use ``make install-aux`` to install some of
the other programs that are in the ``aux/zeek-aux`` directory.

Finally, if you want to build the Zeek documentation (not required, because
all of the documentation for the latest Zeek release is available on the
Zeek web site), there are instructions in ``doc/README`` in the source
distribution.

Cross Compiling
---------------

See :doc:`cross-compiling` for an example of how
to cross compile Zeek for a different target platform than the one on
which you build.

Configure the Run-Time Environment
==================================

You may want to adjust your ``PATH`` environment variable
according to the platform/shell/package you're using.  For example:

Bourne-Shell Syntax:

.. sourcecode:: console

   export PATH=/usr/local/zeek/bin:$PATH

C-Shell Syntax:

.. sourcecode:: console

   setenv PATH /usr/local/zeek/bin:$PATH

Or substitute ``/opt/zeek/bin`` instead if you installed from a binary package.

