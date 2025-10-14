
.. _CMake: https://www.cmake.org
.. _SWIG: http://www.swig.org
.. _Xcode: https://developer.apple.com/xcode/
.. _MacPorts: http://www.macports.org
.. _Fink: http://www.finkproject.org
.. _Homebrew: https://brew.sh
.. _downloads page: https://zeek.org/get-zeek
.. _devtoolset: https://developers.redhat.com/products/developertoolset/hello-world
.. _zkg package manager: https://docs.zeek.org/projects/package-manager/en/stable/
.. _crosstool-NG: https://crosstool-ng.github.io/
.. _CMake toolchain: https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html
.. _contribute: https://github.com/zeek/zeek/wiki/Contribution-Guide
.. _Chocolatey: https://chocolatey.org
.. _Npcap: https://npcap.com/

.. _installing-zeek:

===============
Installing Zeek
===============

To run Zeek, grab our official Docker images, download our Linux binary
packages, install via Homebrew on your Mac, use the ports collections on FreeBSD
and OpenBSD, or build Zeek yourself. For details about our release cadence
and the significance of Zeek's version numbers, please refer to our `Release
Cadence <https://github.com/zeek/zeek/wiki/Release-Cadence>`_ wiki page.

.. _docker-images:

Docker Images
=============

We provide official Docker images on Docker Hub at https://hub.docker.com/u/zeek

    * For the latest feature release: ``docker pull zeek/zeek:latest``
    * For the latest LTS release: ``docker pull zeek/zeek:lts``
    * For the latest release in a given series: ``docker pull zeek/zeek:5.2``
    * For a specific release: ``docker pull zeek/zeek:6.0.0``
    * For the nightly build: ``docker pull zeek/zeek-dev:latest``

Additionally, we push these images to Amazon's Public Elastic Container
Registry (ECR) into the `Zeek Project <https://gallery.ecr.aws/zeek>`_
public gallery. To use Amazon's container registry instead of Docker Hub,
prefix images with ``public.ecr.aws/zeek`` instead of ``zeek``.

    * For instance, to pull the latest feature release: ``docker pull public.ecr.aws/zeek/zeek:latest``

The images are Debian-based and feature a complete Zeek installation with ``zeek``,
``zkg``, and the Spicy toolchain, but are otherwise minimal to avoid bloat in
derived images. For example, if you'd like to install Zeek plugins in those
images, you'll need to install their needed toolchain, typically at least
``g++`` for compilation, ``cmake`` and ``make`` as build tools, and
``libpcap-dev`` to build against Zeek headers. Similarly, you'll need ``g++``
for Spicy's JIT compilation, as well as ``cmake`` and ``make`` to build Spicy
analyzer packages.

  .. code-block:: console

    apt-get update
    apt-get install -y --no-install-recommends g++ cmake make libpcap-dev

The source files used to create the container images are on
`GitHub <https://github.com/zeek/zeek/blob/master/docker>`_.

.. _binary-packages:

Binary Packages
===============

Linux
-----

We provide `binary packages <https://build.opensuse.org/project/show/security:zeek>`_
for a wide range of Linux distributions via the `openSUSE Build Service
<https://build.opensuse.org/>`_. To install, first add the relevant OBS
package repository to your system, then use your system's package manager
as usual.

We provide the following groups of packages:

    * ``zeek-X.0``: specific LTS release lines, currently `5.0.x <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-5.0>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-5.0>`__) and `6.0.x <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-6.0>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-6.0>`__)
    * ``zeek``: the `latest Zeek release <https://software.opensuse.org//download.html?project=security%3Azeek&package=zeek>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek>`__)
    * ``zeek-nightly``: our `nightly builds <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-nightly>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-nightly>`__)
    * ``zeek-rc``: our `release candidates <https://software.opensuse.org/download.html?project=security%3Azeek&package=zeek-rc>`_ (`sources <https://build.opensuse.org/package/show/security:zeek/zeek-rc>`__)

For example, for the latest Zeek 6.0 LTS release on Ubuntu 22.04 the steps look as follows:

  .. code-block:: console

     echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
     curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
     sudo apt update
     sudo apt install zeek-6.0

.. note:: Our motivation for this approach is twofold. First, it guarantees LTS
   users that they won't unexpectedly end up on a newer LTS line when it comes
   out. For example, when you install the ``zeek-6.0`` packages, you will not
   end up on Zeek 7.0 until you decide to switch. Second, it reflects the fact
   that we consider our x.1 and x.2 feature release lines transient, because
   they go out of support immediately once we move to the next line of feature
   releases. Therefore, users of the ``zeek`` packages automatically obtain the
   latest releases as we publish them.

   In the past our binary packages also automatically transitioned our LTS users
   to newer versions, via the older ``zeek-lts`` packages. These remain visible
   on OBS but are no longer supported.

The primary install prefix for binary packages is :file:`/opt/zeek` (depending
on which version you’re using), and includes a complete Zeek environment with
``zeek`` itself, the ``zkg`` package manager, the Spicy toolchain, etc.

See our `Binary Packages wiki page <https://github.com/zeek/zeek/wiki/Binary-Packages>`_
for the latest updates on binary releases.

macOS
-----

The Zeek `Homebrew formula <https://formulae.brew.sh/formula/zeek>`_
provides binary packages ("bottles"). To install:

  .. code-block:: console

     brew install zeek

These packages are not maintained by the Zeek project.

FreeBSD
-------

Zeek is available from the `FreeBSD ports collection <https://www.freshports.org/security/zeek>`_.
To install:

  .. code-block:: console

     sudo pkg install -y zeek

These packages are not maintained by the Zeek project.

OpenBSD
-------

Zeek is available from the `OpenBSD ports collection <https://openports.se/net/bro>`_.
To install:

  .. code-block:: console

     sudo pkg_add zeek

These packages are not maintained by the Zeek project.

Building from Source
====================

Building Zeek from source provides the most control over your build and is the
preferred approach for advanced users. We support a wide range of operating
systems and distributions. Our `support policy
<https://github.com/zeek/zeek/wiki/Platform-Support-Policy>`_ is informed by
what we can run in our CI pipelines with reasonable effort, with the current
status captured in our `support matrix
<https://github.com/zeek/zeek/wiki/Zeek-Operating-System-Support-Matrix>`_.

Required Dependencies
---------------------

Building Zeek from source requires the following dependencies, including
development headers for libraries:

    * Bash (for ZeekControl and BTest)
    * BIND8 library or greater (if not covered by system's libresolv)
    * Bison 3.3 or greater (https://www.gnu.org/software/bison/)
    * C/C++ compiler with C++17 support (GCC 8+ or Clang 9+)
    * CMake 3.15 or greater (https://www.cmake.org)
    * Flex (lexical analyzer generator) 2.6 or greater (https://github.com/westes/flex)
    * Libpcap (http://www.tcpdump.org)
    * Make
    * OpenSSL (http://www.openssl.org)
    * Python 3.7 or greater (https://www.python.org/)
    * SWIG (http://www.swig.org)
    * Zlib (https://zlib.net/)

To install these, you can use:

* RPM/RedHat-based Linux:

  .. code-block:: console

     sudo dnf install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python3 python3-devel swig zlib-devel

  On pre-``dnf`` systems, use ``yum`` instead.  Additionally, on RHEL/CentOS 7,
  you can install and activate a devtoolset_ to get access to recent GCC
  versions. You will also have to install and activate CMake 3.  For example:

  .. code-block:: console

     sudo yum install cmake3 devtoolset-7
     scl enable devtoolset-7 bash

* DEB/Debian-based Linux:

  .. code-block:: console

     sudo apt-get install cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

* FreeBSD:

  Most required dependencies should come with a minimal FreeBSD install
  except for the following.

  .. code-block:: console

      sudo pkg install -y bash git cmake swig bison python3 base64
      pyver=`python3 -c 'import sys; print(f"py{sys.version_info[0]}{sys.version_info[1]}")'`
      sudo pkg install -y $pyver-sqlite3

* macOS:

  Compiling source code on Macs requires first installing either Xcode_
  or the "Command Line Tools" (which is a much smaller download).  To check
  if either is installed, run the ``xcode-select -p`` command.  If you see
  an error message, then neither is installed and you can then run
  ``xcode-select --install`` which will prompt you to either get Xcode (by
  clicking "Get Xcode") or to install the command line tools (by
  clicking "Install").

  macOS comes with all required dependencies except for CMake_, SWIG_,
  Bison, Flex, and OpenSSL (OpenSSL headers were removed in macOS 10.11,
  therefore OpenSSL must be installed manually for macOS versions 10.11
  or newer).

  Distributions of these dependencies can likely be obtained from your
  preferred macOS package management system (e.g. Homebrew_,
  MacPorts_, or Fink_). Specifically for Homebrew, the ``cmake``,
  ``swig``, ``openssl``, ``bison``, and ``flex`` packages
  provide the required dependencies.  For MacPorts, the ``cmake``,
  ``swig``, ``swig-python``, ``openssl``, ``bison``, and ``flex`` packages
  provide the required dependencies.

* Windows

  Windows support is experimental. These instructions are meant as a starting
  point for development on that platform, and might have issues or be missing
  steps. Notify the Zeek team if any such problems arise.

  Compiling on Windows requires the installation of a development environment.
  Zeek currently builds on Visual Studio 2019, and you can either install the
  full version including the UI tools or you can install the command-line tools
  and build from a shell. The instructions below describe how to install the
  command-line tools, but are not necessary if you install the full VS2019
  package. You will need to install Chocolatey_ in order to install the
  dependencies as instructed below. It's possible to install them from other
  sources (msys2, cygwin, etc), which we leave to the reader.

  Cloning the repository will also require Developer Mode to be enabled in
  Windows. This is due to the existence of a number of symbolic links in the
  repository. Without Developer Mode, ``git`` on Windows will ignore these
  links and builds will fail. There are a couple of different ways to enable
  it, and the settings may differ depending on the version of Windows.

  .. code-block:: console

     choco install -y --no-progress visualstudio2019buildtools --version=16.11.11.0
     choco install -y --no-progress visualstudio2019-workload-vctools --version=1.0.0 --package-parameters '--add Microsoft.VisualStudio.Component.VC.ATLMFC'
     choco install -y --no-progress sed
     choco install -y --no-progress winflexbison3
     choco install -y --no-progress msysgit
     choco install -y --no-progress python
     choco install -y --no-progress openssl --version=3.1.1

  Once the dependencies are installed, you will need to add the Git installation
  to your PATH (``C:\Program Files\Git\bin`` by default). This is needed for the
  ``sh`` command to be available during the build. Once all of the dependencies
  are in place, you will need to open a shell (PowerShell or cmd) and add the
  development environment to it. The following command is for running on an
  x86_64 host.

  .. code-block:: console

     C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvarsall.bat x86_amd64

  Now you can build via cmake:

  .. code-block:: console

     mkdir build
     cd build
     cmake.exe .. -DCMAKE_BUILD_TYPE=release -DENABLE_ZEEK_UNIT_TESTS=yes -DVCPKG_TARGET_TRIPLET="x64-windows-static" -G Ninja
     cmake.exe --build .

  All of this is duplicated in the CI configuration for Windows which lives in
  the ``ci/windows`` directory, and can be used as a reference for running the
  commands by hand.

  Note: By default, Windows links against the standard libpcap library from
  vcpkg. This version of libpcap does not support packet capture on Windows,
  unlike other platforms. In order to capture packets from live interfaces on
  Windows, you will need to link against the Npcap_ libary. This library is free
  for personal use, but requires a paid license for commercial use or
  redistribution. To link against Npcap, download the SDK from their website,
  unzip it, and then pass ``-DPCAP_ROOT_DIR="<path to npcap sdk>"`` to the
  initial CMake invocation for Zeek.


Optional Dependencies
---------------------

Zeek can make use of some optional libraries and tools if they are found at
build time:

    * libmaxminddb (for geolocating IP addresses)
    * sendmail (enables Zeek and ZeekControl to send mail)
    * curl (used by a Zeek script that implements active HTTP)
    * gperftools (tcmalloc is used to improve memory and CPU usage)
    * jemalloc (https://github.com/jemalloc/jemalloc)
    * PF_RING (Linux only, see :ref:`pf-ring-config`)
    * krb5 libraries and headers
    * ipsumdump (for trace-summary; https://github.com/kohler/ipsumdump)

Geolocation is probably the most interesting and can be installed on most
platforms by following the instructions for :ref:`address geolocation and AS
lookups <geolocation>`.

The `zkg package manager`_, included in the Zeek installation, requires
two external Python modules:

    * GitPython: https://pypi.org/project/GitPython/
    * semantic-version: https://pypi.org/project/semantic-version/

These install easily via pip (``pip3 install GitPython
semantic-version``) and also ship with some distributions:

* RPM/RedHat-based Linux:

  .. code-block:: console

     sudo yum install python3-GitPython python3-semantic_version

* DEB/Debian-based Linux:

  .. code-block:: console

     sudo apt-get install python3-git python3-semantic-version

``zkg`` also requires a ``git`` installation, which the above system packages
pull in as a dependency. If you install via pip, remember that you also need
``git`` itself.

Retrieving the Sources
----------------------

Zeek releases are bundled into source packages for convenience and are
available on the `downloads page`_. The source code can be manually downloaded
from the link in the ``.tar.gz`` format to the target system for installation.

If you plan to `contribute`_ to Zeek or just want to try out the latest
features under development, you should obtain Zeek's source code through its
Git repositories hosted at https://github.com/zeek:

.. code-block:: console

    git clone --recurse-submodules https://github.com/zeek/zeek

.. note:: If you choose to clone the ``zeek`` repository
   non-recursively for a "minimal Zeek experience", be aware that
   compiling it depends on several of the other submodules as well, so
   you'll likely have to build/install those independently first.

Configuring and Building
------------------------

The typical way to build and install from source is as follows:

.. code-block:: console

    ./configure
    make
    make install

If the ``configure`` script fails, then it is most likely because it either
couldn't find a required dependency or it couldn't find a sufficiently new
version of a dependency.  Assuming that you already installed all required
dependencies, then you may need to use one of the ``--with-*`` options
that can be given to the ``configure`` script to help it locate a dependency.
To find out what all different options ``./configure`` supports, run
``./configure --help``.

The default installation path is ``/usr/local/zeek``, which would typically
require root privileges when doing the ``make install``.  A different
installation path can be chosen by specifying the ``configure`` script
``--prefix`` option.  Note that ``/usr``, ``/opt/bro/``, and ``/opt/zeek`` are
the standard prefixes for binary Zeek packages to be installed, so those are
typically not good choices unless you are creating such a package.

OpenBSD users, please see our `FAQ <https://zeek.org/faq/>`_ if you are having
problems installing Zeek.

Depending on the Zeek package you downloaded, there may be auxiliary
tools and libraries available in the ``auxil/`` directory. Some of them
will be automatically built and installed along with Zeek. There are
``--disable-*`` options that can be given to the configure script to
turn off unwanted auxiliary projects that would otherwise be installed
automatically.  Finally, use ``make install-aux`` to install some of
the other programs that are in the ``auxil/zeek-aux`` directory.

Finally, if you want to build the Zeek documentation (not required, because
all of the documentation for the latest Zeek release is available at
https://docs.zeek.org), there are instructions in ``doc/README`` in the source
distribution.

Cross Compiling
---------------

Prerequisites
~~~~~~~~~~~~~

You need three things on the host system:

1. The Zeek source tree.
2. A cross-compilation toolchain, such as one built via crosstool-NG_.
3. Pre-built Zeek dependencies from the target system.  This usually
   includes libpcap, zlib, OpenSSL, and Python development headers
   and libraries.

Configuration and Compiling
~~~~~~~~~~~~~~~~~~~~~~~~~~~

You first need to compile a few build tools native to the host system
for use during the later cross-compile build.  In the root of your
Zeek source tree:

.. code-block:: console

   ./configure --builddir=../zeek-buildtools
   ( cd ../zeek-buildtools && make binpac bifcl )

Next configure Zeek to use your cross-compilation toolchain (this example
uses a Raspberry Pi as the target system):

.. code-block:: console

   ./configure --toolchain=/home/jon/x-tools/RaspberryPi-toolchain.cmake --with-binpac=$(pwd)/../zeek-buildtools/auxil/binpac/src/binpac --with-bifcl=$(pwd)/../zeek-buildtools/src/bifcl

Here, the :file:`RaspberryPi-toolchain.cmake` file specifies a `CMake
toolchain`_.  In the toolchain file, you need to point the toolchain and
compiler at the cross-compilation toolchain.  It might look something the
following:

.. code-block:: cmake

  # Operating System on which CMake is targeting.
  set(CMAKE_SYSTEM_NAME Linux)

  # The CMAKE_STAGING_PREFIX option may not work.
  # Given that Zeek is configured:
  #
  #   `./configure --prefix=<dir>`
  #
  # The options are:
  #
  #   (1) `make install` and then copy over the --prefix dir from host to
  #       target system.
  #
  #   (2) `DESTDIR=<staging_dir> make install` and then copy over the
  #       contents of that staging directory.

  set(toolchain /home/jon/x-tools/arm-rpi-linux-gnueabihf)
  set(CMAKE_C_COMPILER   ${toolchain}/bin/arm-rpi-linux-gnueabihf-gcc)
  set(CMAKE_CXX_COMPILER ${toolchain}/bin/arm-rpi-linux-gnueabihf-g++)

  # The cross-compiler/linker will use these paths to locate dependencies.
  set(CMAKE_FIND_ROOT_PATH
      /home/jon/x-tools/zeek-rpi-deps
      ${toolchain}/arm-rpi-linux-gnueabihf/sysroot
  )

  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

If that configuration succeeds you are ready to build:

.. code-block:: console

   make

And if that works, install on your host system:

.. code-block:: console

   make install

Once installed, you can copy/move the files from the installation prefix on the
host system to the target system and start running Zeek as usual.

Configuring the Run-Time Environment
====================================

You may want to adjust your :envvar:`PATH` environment variable
according to the platform/shell/package you're using since
neither :file:`/usr/local/zeek/bin/` nor :file:`/opt/zeek/bin/`
will reside in the default :envvar:`PATH`. For example:

Bourne-Shell Syntax:

.. code-block:: console

   export PATH=/usr/local/zeek/bin:$PATH

C-Shell Syntax:

.. code-block:: console

   setenv PATH /usr/local/zeek/bin:$PATH

Or substitute ``/opt/zeek/bin`` instead if you installed from a binary package.

Zeek supports several environment variables to adjust its behavior. Take a look
at the ``zeek --help`` output for details.
