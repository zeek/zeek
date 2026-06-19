.. _devel-btest:


Testing with BTest
==================

Zeek's main regression tests are `btest <https://github.com/zeek/btest>`_-based.

Testing protocol parsers (also called analyzers) and scripting behavior is
usually done by having Zeek read packet traces (PCAP files) to produce logs.
These logs are then baselined. Baselines are stored in the
testing/btest/Baseline directory and checked into the repository.

There's also a Baseline.zam directory for alternative baselines when
running Zeek with :ref:`ZAM <zam>` enabled.

All btests run in CI on various platforms with and without ZAM enabled.


Packet Traces (PCAP Files)
--------------------------

We store packet traces in testing/btest/Traces/. The README file represents an
index where PCAPs came from or how they were created to keep a bit of lineage
available. PCAP filenames always end with ``.pcap`` or ``.pcapng``. Usually PCAP
files are stored uncompressed, except for some larger but highly compressible examples.

There are generally two approaches to create new packet traces in isolation
if you cannot share a packet capture from a production network.
Either install and run the software yourself and capture the traffic
with ``tcpdump`` in a lab or virtual environment, or
create a Python script that produces packet traces using
`Scapy <https://github.com/secdev/scapy>`_. LLM agents are very
effective for the latter. Including packet traces from real software or
actual production networks is more realistic and if available, preferred
over Scapy-generated traces. For edge case testing of parsers, Scapy-generated,
Scapy-edited, or hex-edited capture files are all fair game. Keep a note in
the README what was done to create a certain trace.

The testing/btest/Traces directory is mostly structured by protocol. When
adding a Scapy-generated trace, ``<name>.pcap``, put a ``<name>.pcap.py``
file next to it. Running the Python script should generate the ``<name>.pcap``
file next to ``<name>.pcap.py`` reproducibly. Running the script a year later
should produce the exact same result. We commit generated PCAP files into
the repository.

Multi-word PCAP names should be all lower-case and use dashes for separation.
The PCAP's name should include the thing or scenario being tested. For example,
``ftp/ftp-with-numbers-in-filename.pcap`` or ``ssh/server-pre-banner-data.pcap``.
Try to keep PCAP files to a few kilobytes in size, 50KB or more should be
an exception. Including PCAPs with valid checksums is preferred. Use ``tcprewrite``
to correct them if needed.

Creating new Tests
------------------

Tests are stored and executed from the testing/btest/ directory. There are
subdirectories for individual Zeek components and protocols. Recursively looking
at directory and test names should help you orient. Older or more integration-like
tests end with ``.test`` or ``.sh``. Most tests using packet traces and
baselining or testing Zeek language features should end with ``.zeek``
for better language server support.

Every test should have a commented ``@TEST-DOC`` line at the top describing
what is being tested, followed by some ``@TEST-EXEC`` lines with the actual
commands.

.. code-block:: shell

    # @TEST-DOC: Verify a basic HTTP GET request.
    #
    # @TEST-EXEC: zeek -b -r $TRACES/http/get.pcap %INPUT
    #
    # @TEST-EXEC: btest-diff-cut -m uid service history conn.log
    # @TEST-EXEC: btest-diff-cut -m http.log

    @load base/protocols/conn
    @load base/protocols/http

In tests, prefer to use ``zeek -b`` to invoke Zeek in bare mode to reduce Zeek's
initialization time and reduce the potential for unintended side-effects. Load
all required scripts and packages via explicit :zeek:see:`@load` directives
within the test's content. The magic ``%INPUT`` variable expands to a filename
containing the content of the test (see the BTest documentation for more details).

The ``$TRACES`` environment variable is set in ``testing/btest/btest.cfg``
and expands to ``testing/btest/Traces``. That's all there is to it.

For baseline testing, ``@TEST-EXEC: btest-diff`` has been used historically,
with ``btest-diff-cut`` being a recent addition that allows to easily create
smaller baselines by selecting relevant columns to diff.
Prefer to use the ``btest-diff-cut`` helper script and only include columns
in the baselines that are relevant to the test. This hardens your test against
irrelevant baseline deviations introduced by unrelated future changes to Zeek.
Avoid the verbose TSV header by passing ``-m`` to ``btest-diff`` or ``btest-diff-cut``.

To baseline all columns of ``path.log``, use ``btest-diff-cut -m path.log``.
A full baseline is recommended for protocol logs in tests that are specific
to that protocol. For example, in HTTP tests, baseline the full ``http.log``,
but only select certain columns from ``conn.log`` as shown above.

The conn.log's uid service and history columns are generally interesting,
even if the test does not strictly need all of them. Checksum errors are
quickly recognized as `c` or `C` in the history column. The service entry
is also useful to verify a protocol is present (and wasn't removed due
to an analyzer violation).

If you baseline weird.log, always include the columns uid, name, addl and
source. You must include ``@load base/frameworks/notice/weird`` in the test
as Zeek does not log weirds when running in bare mode.

When testing very specific analyzer confirmation and violation behavior, load
the ``frameworks/analyzer/debug-logging.zeek`` and baseline the created
``analyzer_debug.log`` using ``btest-diff-cut -m``:

.. code-block:: shell

    # @TEST-DOC: Verify the SSH analyzer's confirmation and violation behavior. Regression test for #1234.
    #
    # @TEST-EXEC: zeek -r $TRACES/ssh/ssh.server-side-half-duplex.pcap %INPUT
    #
    # @TEST-EXEC: btest-diff-cut -m ssh.log
    # @TEST-EXEC: btest-diff-cut -m uid service history conn.log
    # @TEST-EXEC: btest-diff-cut -m analyzer_debug.log

    @load base/protocols/ssh
    @load frameworks/analyzer/debug-logging.zeek

If you explicitly want to test for no weirds or no analyzer violations,
use ``test ! -f weird.log``:

.. code-block:: shell

    # ...
    # @TEST-EXEC: btest-diff-cut -m uid service history conn.log
    #
    # @TEST-EXEC: test ! -f weird.log
    # @TEST-EXEC: test ! -f analyzer.log

    @load base/protocols/conn
    @load base/protocols/http
    @load base/frameworks/notice/weird

The ``btest-diff`` and ``btest-diff-cut`` commands support ``TEST_DIFF_CANONFIER``
to *canonify* a baseline, i.e., normalize content that will change from invocation
to invocation. It defaults to ``testing/scripts/diff-canonifier``, which is set in
``testing/btest/btest.cfg`` and canonifies timestamps to a ``XXXX.XXX`` pattern.

When testing specific events, a common pattern is to implement one or more
event handlers in the test script and use print to output the interesting
information, conventionally prepended with the event name.
To capture the output, we usually redirect into a file named ``out`` and use
``btest-diff`` on it:

.. code-block:: shell

        # @TEST-DOC: Test the geneve_packet() event.
        #
        # @TEST-EXEC: zeek -b -r $TRACES/tunnels/geneve.pcap %INPUT >out
        #
        # @TEST-EXEC: btest-diff out
        # @TEST-EXEC: btest-diff -m uid service history conn.log

        @load base/protocols/conn

        event geneve_packet(c: connection, inner: pkt_hdr, vni: count)
                {
                print "geneve_packet", c$id, inner, vni;
                }

Sometimes tests exists only to execute Zeek and observe no crashes or ASAN
or UBSAN violations, but often these handle a specific event and the ``out``
pattern is used, even if not strictly needed.


Verification
------------

Always verify that new tests pass by running them with ``btest -d path/to/test``
in the top-level ``testing/btest`` directory. Ensure all required files are included
in a commit and PR submission (new PCAP files, new baselines, new tests).

Finally, also verify that all tests still pass by running ``btest -d -j`` in the
top-level ``testing/btest`` directory. When adding new scripts or fields to record
types, some tests in ``./coverage`` require updates. To only run the coverage
tests, pass the directory to btest: ``btest -d -j ./coverage``.

To update baselines, run ``btest -d -U path/to/test``. Note that this batch
updates all ``btest-diff`` and ``btest-diff-cut`` baselines at once.
Use ``btest -d -u`` for interactive prompts.
In either case, verify with ``git diff`` or ``git diff --word-diff`` after
running an update to validate the baseline changes are reasonable. When
adding new tests, don't forget to stage the new baselines before committing.
BTest stores baselines in a directory named testing/Baseline/relative.path.to.test/
(or starting with Baseline.zam). Essentially, slashes in the relative path
starting testing/btest are replaced with dots. This can be a bit confusing initially.

To run all tests with ZAM, use ``btest -d -j -a zam``. Look into btest's
environment concept and check ``testing/btest/btest.cfg`` for the extra
environment variables and settings used for running tests under ZAM.


Non-PCAP Tests
--------------

Note that not all tests are packet trace based. Many of the cluster tests instead
use ``btest-bg-run``, ``btest-bg-wait`` and remote events for testing. Review them
first if you work on cluster functionality. There are also the ``./bifs`` and
``./language`` directories that usually do not involve packet traces unless
required for driving network time for timer or table expiration testing.
Deep dive into tests if you need to learn how exactly they work.
