Fuzz Testing
============

This directory contains fuzzing targets for various Zeek components.  The
primary way to use these directly would be with a fuzzing engine such as
libFuzzer: https://llvm.org/docs/LibFuzzer.html

Example Build: Initial Fuzzing and Seed Corpus
----------------------------------------------

First configure and build for fuzzing (with libFuzzer) and code coverage::

    $ LIB_FUZZING_ENGINE="" CC=clang CXX=clang++ \
      ./configure --build-type=debug --build-dir=./build-fuzz-cov \
      --sanitizers=fuzzer-no-link --enable-fuzzers --enable-coverage

    $ cd build-fuzz-cov && make -j $(nproc)

.. note::

   The default assumption for empty value of ``LIB_FUZZING_ENGINE`` is to use
   libFuzzer by linking with ``-fsanitize=fuzzer``, but that environment
   variable may be changed to use another flag or direct path to fuzzing engine
   library to link against.

Text/Dictionary-based Corpus
````````````````````````````

Now start fuzzing to generate an initial corpus (this uses the POP3 fuzzer as
an example)::

    $ mkdir corpus && ./src/fuzzers/zeek-pop3-fuzzer corpus \
      -dict=../src/fuzzers/pop3.dict -max_total_time=300 -fork=$(($(nproc) - 1))

You can set options, like the runtime and parallelism level, to taste.  For
other fuzz targets, you'd also want to use a different dictionary or omit
entirely.

To minimize the size of the corpus::

    $ mkdir min-corpus && ./src/fuzzers/zeek-pop3-fuzzer -merge=1 min-corpus corpus

To check the code coverage of the corpus::

    $ ./src/fuzzers/zeek-pop3-fuzzer min-corpus/*

    $ llvm-cov gcov $(find . -name POP3.cc.gcda) | grep -A1 POP3.cc

    # Annotated source file is now output to POP3.cc.gcov

If the code coverage isn't satisfying, there may be something wrong with
the fuzzer, it may need a better dictionary, or it may need to fuzz for longer.

The corpus can be added to revision control for use in regression testing and
as seed for OSS-Fuzz (check first that the zip file is a size that's sane to
commit)::

    zip -j ../src/fuzzers/pop3-corpus.zip min-corpus/*

pcap-based Corpus
`````````````````

A corpus can also be generated from representative pcp files using the
``pcap-to-pkt`` application from pcap_simplify_. The fuzzers only handle a
single connection at a time, so pcap files with multiple connections will
need to be split using ``PcapSplitter`` from PcapPlusPlus_ or something
similar. Once the file has been split, the individual connections can be
converted into separate pkt files. The ``http`` fuzzer is a good example
of a fuzzer using such files. The corpus for that fuzzer was initially
generated from a subset of the pcap files located in ``testing/btest/Traces/http``.

.. _pcap_simplify: https://github.com/JustinAzoff/pcap_simplify
.. _PcapPlusPlus: https://github.com/seladb/PcapPlusPlus

The converted pkt files can then be zipped as in the text-based section
above.

Example Build: Run Standalone Fuzz Targets
------------------------------------------

Fuzz targets can still be run without a fuzzing engine driving them.  In
standalone mode, they'll process all input files provided as arguments
(e.g. useful for regression testing).

First configure and build::

    $ ./configure --build-type=debug --build-dir=./build-fuzz-check \
      --sanitizers=address --enable-fuzzers

    $ cd build-fuzz-check && make -j $(nproc)

Get a set of inputs to process (we're using the POP3 fuzzer/corpus as example)::

    $ mkdir corpus && ( cd corpus && unzip ../../src/fuzzers/pop3-corpus.zip )

Now run the standalone fuzzer on the input corpus::

    $ ./src/fuzzers/zeek-pop3-fuzzer corpus/*

Note that you can also configure this build for coverage reports to verify the
code coverage (see the CFLAGS/CXXFLAGS from the first "Initial Fuzzing"
section).  There's also the following ASan option which may need to be used::

    $ export ASAN_OPTIONS=detect_odr_violation=0

OSS-Fuzz Integration
--------------------

The OSS-Fuzz integration is all contained in the external OSS-Fuzz repo's
Zeek project: https://github.com/google/oss-fuzz

There's not much to it other than Dockerfile and build script, but a couple
conventions to follow to support the OSS-Fuzz configuration:

* Fuzz target names are all like ``zeek-*-fuzzer``.  The OSS-Fuzz build
  scripts expects that and won't pick up any fuzzer that are named differently.

* Fuzzers should expect to have to load Zeek scripts from a directory named
  ``oss-fuzz-zeek-scripts`` that lives next to the fuzzer executable.  When
  running fuzzers locally, the usual way of setting ``ZEEKPATH`` from the build
  directory does still work, but fuzzers should additionally augment
  ``ZEEKPATH`` with that special OSS-Fuzz scripts directory so they'll be able
  to run in that environment.
