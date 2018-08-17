.. _crosstool-NG: https://crosstool-ng.github.io/
.. _CMake toolchain: https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html

===================
Cross Compiling Bro
===================

.. contents::

Prerequisites
=============

You need three things on the host system:

1. The Bro source tree.
2. A cross-compilation toolchain, such as one built via crosstool-NG_.
3. Pre-built Bro dependencies from the target system.  This usually
   includes libpcap, zlib, OpenSSL, and Python development headers
   and libraries.

Configuration and Compiling
===========================

You first need to compile a few build tools native to the host system
for use during the later cross-compile build.  In the root of your
Bro source tree:

.. console::

   ./configure --builddir=../bro-buildtools
   ( cd ../bro-buildtools && make binpac bifcl )

Next configure Bro to use your cross-compilation toolchain:

.. console::

   ./configure --toolchain=/home/jon/x-tools/RaspberryPi-toolchain.cmake --with-binpac=$(pwd)/../bro-buildtools/aux/binpac/src/binpac --with-bifcl=$(pwd)/../bro-buildtools/src/bifcl

Here, the toolchain file a `CMake toolchain`_ file.  It might look
something the following (using a Raspberry Pi as target system)::

  # Operating System on which CMake is targeting.
  set(CMAKE_SYSTEM_NAME Linux)

  # The CMAKE_STAGING_PREFIX option may not work.
  # Given that Bro is configured:
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
      /home/jon/x-tools/bro-rpi-deps
      ${toolchain}/arm-rpi-linux-gnueabihf/sysroot
  )

  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

If that configuration succeeds you are ready to build:

.. console::

   make

And if that works, install on your host system:

.. console::

   make install

From there, you can copy/move the files from the installation prefix
on the host system to the target system and start running Bro as usual.
