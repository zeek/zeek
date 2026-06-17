.. _devel-hacking:

Hacking on Zeek
===============

A few notes and tips useful when starting to hack on Zeek.

Building
--------

Install dependencies as listed in :ref:`Building from Source <building-from-source>`
for your development environment.

Clone the repo and initialize all git submodules:

.. code-block:: shell

    # git clone https://github.com/zeek/zeek zeek
    # cd zeek
    # git submodule update --init --recursive

Configure and build Zeek using the Ninja generator with Debug settings.

.. code-block:: shell

    # ./configure --build-type=Debug --generator=Ninja
    # ninja -C build

Once the build has completed, source the generated ``build/zeek-path-dev.sh``
script. This script sets various environment variables and lets you run Zeek
directly from the ``./build`` directory without needing to install:

.. code-block:: shell

   # . ./build/zeek-path-dev.sh
   # zeek -e 'print "Hello World"'
   Hello World!

To run all of Zeek's regression tests after the build completed:

.. code-block:: shell

   # cd testing/btest
   # btest -d -j

See the separate :ref:`devel-btest` section to learn about testing.

To build Zeek with the ASAN sanitizer enabled into a separate
build directory named ``asan-build``:

.. code-block:: shell

    # ./configure --build-type=Debug --sanitizer=address --build-dir=asan-build
    # ninja -C asan-build
    # . ./asan-build/zeek-path-dev.sh

To run the regression tests using the Zeek build in the ``asan-build`` directory,
pass the ``build_dir`` variable to the btest invocation:

.. code-block:: shell

   # cd testing/btest
   # btest -s build_dir=asan-build -d -j


Tips
----

ccache
^^^^^^

Zeek takes a long time to build. We recommend using `ccache <https://ccache.dev/>`_
for local development to reuse compilation artifacts for improved iteration speeds:

.. code-block:: shell

    # ./configure --generator=Ninja --ccache

lld or mold
^^^^^^^^^^^

The Zeek executable takes a fairly long time to link when using the default
linker ld on Linux and ccache doesn't help here. Using `lld <https://lld.llvm.org/>`_
or `mold <https://github.com/rui314/mold>`_ significantly speeds up the linking
steps. Set the LDFLAGS environment variable to switch the linker used:

.. code-block:: shell

    # LDFLAGS=-fuse-lld ./configure --generator=Ninja --ccache

On OSX or FreeBSD, lld is used by default. This is primarily relevant
if you work on Linux with GCC as default.

CMake
^^^^^

The ``configure`` script is really just a small wrapper invoking ``cmake``. To pass
arbitrary CMake options that aren't exposed via dedicated ``configure`` flags,
use the ``-D`` argument. For example, disabling the ZeroMQ cluster backend:

.. code-block:: shell

    # ./configure --generator=Ninja --ccache -D ENABLE_CLUSTER_BACKEND_ZEROMQ=no

jemalloc
^^^^^^^^

Using `jemalloc <https://github.com/jemalloc/jemalloc>`_ as allocator provides
a significant runtime performance boost for Zeek and also comes with various
debugging, profiling and troubleshooting facilities. Consider always compiling
using ``--enable-jemalloc`` and ensure your version of jemalloc has profiling
enabled:

.. code-block:: shell

    # ./configure --generator=Ninja --ccache --enable-jemalloc

Alternatively, set ``LD_PRELOAD=/usr/local/lib/libjemalloc.so`` when
running Zeek.

See also :ref:`Troubleshooting <troubleshooting>`.

Compile Commands
^^^^^^^^^^^^^^^^

Zeek automatically creates ``compile_commands.json`` in the build directory
and you can point language servers, IDEs, ``pahole``, ``clang-tidy``,
etc. at ``./build``:

.. code-block:: shell

    # clang-tidy-20  -p build ./src/packet_analysis/protocol/null/Null.cc


Debug Streams
-------------

To use Zeek's debug stream facility, first verify with ``-B help`` that
debug streams are available (only when ``--build-type=Debug`` was used).

.. code-block:: shell

    # zeek -B help
    Enable debug output into debug.log with -B <streams>.
    <streams> is a case-insensitive, comma-separated list of streams to enable:

    broker
    cluster
    dpd
    ...

When debug streams are not available, the output is as follows:

.. code-block:: shell

    # zeek -B help
    debug streams unavailable


By default, the debug stream output is written into a ``debug.log`` file
in the current working directory. Set the environment variable
``ZEEK_DEBUG_LOG_STDERR=1`` to enable output to stderr.

Instead of using ``-B``, debug streams can be enabled by setting the
environment variable ``ZEEK_DEBUG_LOG_STREAMS=dpd``. This is useful
for producing a ``debug.log`` file when running btests without needing
to modify the Zeek invocation within the test itself:

.. code-block:: shell

    # ZEEK_DEBUG_LOG_STREAMS=plugin-Zeek-Cluster_Backend_ZeroMQ btest -t -d ./cluster/zeromq/two-nodes.zeek
    # tail -4  .tmp/cluster.zeromq.two-nodes/worker/debug.log
    1781706388.639783/1781706388.640376 [plugin Zeek::Cluster_Backend_ZeroMQ] Joined self_thread
    1781706388.639783/1781706388.640395 [plugin Zeek::Cluster_Backend_ZeroMQ] Shutting down ctx
    1781706388.639783/1781706388.640412 [plugin Zeek::Cluster_Backend_ZeroMQ] Closing ctx
    1781706388.639783/1781706388.641006 [plugin Zeek::Cluster_Backend_ZeroMQ] Terminated
