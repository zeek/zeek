..	-*- mode: rst-mode -*-
..
.. Version number is filled in automatically.
.. |version| replace:: 0.4-14

============================================
BTest - A Simple Driver for Basic Unit Tests
============================================

.. rst-class:: opening

    The ``btest`` is a simple framework for writing unit tests. Freely
    borrowing some ideas from other packages, it's main objective is to
    provide an easy-to-use, straightforward driver for a suite of
    shell-based tests. Each test consists of a set of command lines that
    will be executed, and success is determined based on their exit
    codes. ``btest`` comes with some additional tools that can be used
    within such tests to compare output against a previously established
    baseline.

.. contents::

Download
========

You can find the latest BTest release for download at
http://www.bro.org/download.

BTest's git repository is located at `git://git.bro.org/btest.git
<git://git.bro.org/btest.git>`__. You can browse the repository
`here <http://git.bro.org/btest.git>`__.

This document describes BTest |version|. See the ``CHANGES``
file for version history.


Installation
============

Installation is simple and standard::

    tar xzvf btest-*.tar.gz
    cd btest-*
    python setup.py install

This will install a few scripts: ``btest`` is the main driver program,
and there are a number of further helper scripts that we discuss below
(including ``btest-diff``, which is a tool for comparing output to a
previously established baseline).

Writing a Simple Test
=====================

In the most simple case, ``btest`` simply executes a set of command
lines, each of which must be prefixed with ``@TEST-EXEC:``
::

    > cat examples/t1
    @TEST-EXEC: echo "Foo" | grep -q Foo
    @TEST-EXEC: test -d .
    > btest examples/t1
    examples.t1 ... ok

The test passes as both command lines return success. If one of them
didn't, that would be reported::

    > cat examples/t2
    @TEST-EXEC: echo "Foo" | grep -q Foo
    @TEST-EXEC: test -d DOESNOTEXIST
    > btest examples/t2
    examples.t2 ... failed

Usually you will just run all tests found in a directory::

    > btest examples
    examples.t1 ... ok
    examples.t2 ... failed
    1 test failed

Why do we need the ``@TEST-EXEC:`` prefixes? Because the file
containing the test can simultaneously act as *its input*. Let's
say we want to verify a shell script::

    > cat examples/t3.sh
    # @TEST-EXEC: sh %INPUT
    ls /etc | grep -q passwd
    > btest examples/t3.sh
    examples.t3 ... ok

Here, ``btest`` is executing (something similar to) ``sh
examples/t3.sh``, and then checks the return value as usual. The
example also shows that the ``@TEST-EXEC`` prefix can appear
anywhere, in particular inside the comment section of another
language.

Now, let's say we want to check the output of a program, making sure
that it matches what we expect. For that, we first add a command
line to the test that produces the output we want to check, and then
run ``btest-diff`` to make sure it matches a previously recorded
baseline. ``btest-diff`` is itself just a script that returns
success if the output is as expected, and failure otherwise. In the
following example, we use an awk script as a fancy way to print all
file names starting with a dot in the user's home directory. We
write that list into a file called ``dots`` and then check whether
its content matches what we know from last time::

    > cat examples/t4.awk
    # @TEST-EXEC: ls -a $HOME | awk -f %INPUT >dots
    # @TEST-EXEC: btest-diff dots
    /^\.+/ { print $1 }

Note that each test gets its own little sandbox directory when run,
so by creating a file like ``dots``, you aren't cluttering up
anything.

The first time we run this test, we need to record a baseline::

    > btest -U examples/t4.awk

Now, ``btest-diff`` has remembered what the ``dots`` file should
look like::

    > btest examples/t4.awk
    examples.t4 ... ok
    > touch ~/.NEWDOTFILE
    > btest examples/t4.awk
    examples.t4 ... failed
    1 test failed

If we want to see what exactly the unexpected change is that was
introduced to ``dots``, there's a *diff* mode for that::

    > btest -d examples/t4.awk
    examples.t4 ... failed
    % 'btest-diff dots' failed unexpectedly (exit code 1)
    % cat .diag
    == File ===============================
    [... current dots file ...]
    == Diff ===============================
    --- /Users/robin/work/binpacpp/btest/Baseline/examples.t4/dots
    2010-10-28 20:11:11.000000000 -0700
    +++ dots      2010-10-28 20:12:30.000000000 -0700
    @@ -4,6 +4,7 @@
    .CFUserTextEncoding
    .DS_Store
    .MacOSX
    +.NEWDOTFILE
    .Rhistory
    .Trash
    .Xauthority
    =======================================

    % cat .stderr
    [... if any of the commands had printed something to stderr, that would follow here ...]

Once we delete the new file, we are fine again::

    > rm ~/.NEWDOTFILE
    > btest -d examples/t4.awk
    examples.t4 ... ok

That's already the main functionality that the ``btest`` package
provides. In the following, we describe a number of further options
extending/modifying this basic approach.

Reference
=========

Command Line Usage
------------------

``btest`` must be started with a list of tests and/or directories
given on the command line. In the latter case, the default is to
recursively scan the directories and assume all files found to be
tests to perform. It is however possible to exclude certain files by
specifying a suitable `configuration file`_.

``btest`` returns exit code 0 if all tests have successfully passed,
and 1 otherwise.

``btest`` accepts the following options:

    -a ALTERNATIVE, --alternative=ALTERNATIVE
        Activates an alternative_ configuration defined in the
        configuration file. This option can be given multiple times to
        run tests with several alternatives. If ``ALTERNATIVE`` is ``-``
        that refers to running with the standard setup, which can be used
        to run tests both with and without alterantives by giving both.

    -b, --brief
        Does not output *anything* for tests which pass. If all tests
        pass, there will not be any output at all.

    -c CONFIG, --config=CONFIG
        Specifies an alternative `configuration file`_ to use. If not
        specified, the default is to use a file called ``btest.cfg``
        if found in the current directory.

    -d, --diagnostics
        Reports diagnostics for all failed tests. The diagnostics
        include the command line that failed, its output to standard
        error, and potential additional information recorded by the
        command line for diagnostic purposes (see `@TEST-EXEC`_
        below). In the case of ``btest-diff``, the latter is the
        ``diff`` between baseline and actual output.

    -D, --diagnostics-all
        Reports diagnostics for all tests, including those which pass.

    -f DIAGFILE, --file-diagnostics=DIAGFILE
        Writes diagnostics for all failed tests into the given file.
        If the file already exists, it will be overwritten.

    -g GROUPS, --group=GROUPS
        Runs only tests assigned to the given test groups, see
        `@TEST-GROUP`_. Multiple groups can be given as a
        comma-separated list. Specifying ``-`` as a group name selects
        all tests that do not belong to any group.

    -j [THREADS], --jobs[=THREADS]
        Runs up to the given number of tests in parallel. If no number
        is given, BTest substitutes the number of available CPU cores
        as reported by the OS.

        By default, BTest assumes that all tests can be executed
        concurrently without further constraints. One can however
        ensure serialization of subsets by assigning them to the same
        serialization set, see `@TEST-SERIALIZE`_.

    -q, --quiet
        Suppress information output other than about failed tests.
        If all tests pass, there will not be any output at all.

    -r, --rerun
        Runs only tests that failed last time. After each execution
        (except when updating baselines), BTest generates a state file
        that records the tests that have failed. Using this option on
        the next run then reads that file back in and limits execution
        to those tests found in there.

    -t, --tmp-keep
        Does not delete any temporary files created for running the
        tests (including their outputs). By default, the temporary
        files for a test will be located in ``.tmp/<test>/``, where
        ``<test>`` is the relative path of the test file with all slashes
        replaced with dots and the file extension removed (e.g., the files
        for ``example/t3.sh`` will be in ``.tmp/example.t3``).

    -U, --update-baseline
        Records a new baseline for all ``btest-diff`` commands found
        in any of the specified tests. To do this, all tests are run
        as normal except that when ``btest-diff`` is executed, it
        does not compute a diff but instead considers the given file
        to be authoritative and records it as the version to compare
        with in future runs.

    -u, --update-interactive
        Each time a ``btest-diff`` command fails in any tests that are
        run, btest will stop and ask whether or not the user wants to
        record a new baseline.

    -v, --verbose
        Shows all test command lines as they are executed.

    -w, --wait
        Interactively waits for ``<enter>`` after showing diagnostics
        for a test.

    -x FILE, --xml=FILE
        Records test results in JUnit XML format to the given file.
        If the file exists already, it is overwritten.

.. _configuration file:

Configuration
-------------

Specifics of ``btest``'s execution can be tuned with a configuration
file, which by default is ``btest.cfg`` if that's found in the
current directory. It can alternatively be specified with the
``--config`` command line option. The configuration file is
"INI-style", and an example comes with the distribution, see
``btest.cfg.example``. A configuration file has one main section,
``btest``, that defines most options; as well as an optional section
for defining `environment variables`_ and further optional sections
for defining alternatives_.

Note that all paths specified in the configuration file are relative
to ``btest``'s *base directory*. The base directory is either the
one where the configuration file is located if such is given/found,
or the current working directory if not. When setting values for
configuration options, the absolute path to the base directory is
available by using the macro ``%(testbase)s`` (the weird syntax is
due to Python's ``ConfigParser`` module).

Furthermore, all values can use standard "backtick-syntax" to
include the output of external commands (e.g., xyz=`\echo test\`).
Note that the backtick expansion is performed after any ``%(..)``
have already been replaced (including within the backticks).

Options
~~~~~~~

The following options can be set in the ``btest`` section of the
configuration file:

``TestDirs``
    A space-separated list of directories to search for tests. If
    defined, one doesn't need to specify any tests on the command
    line.

``TmpDir``
    A directory where to create temporary files when running tests.
    By default, this is set to ``%(testbase)s/.tmp``.

``BaselineDir``
    A directory where to store the baseline files for ``btest-diff``.
    By default, this is set to ``%(testbase)s/Baseline``.

``IgnoreDirs``
    A space-separated list of relative directory names to ignore
    when scanning test directories recursively. Default is empty.

``IgnoreFiles``
    A space-separated list of filename globs matching files to
    ignore when scanning given test directories recursively.
    Default is empty.

``StateFile``
    The name of the state file to record the names of failing tests. Default is
    ``.btest.failed.dat``.

``Finalizer``
    An executable that will be executed each time any test has
    successfully run. It runs in the same directory as the test itself
    and receives the name of the test as its parameter. The return
    value indicates whether the test should indeed be considered
    successful. By default, there's no finalizer set.

.. _environment variables:

Environment Variables
~~~~~~~~~~~~~~~~~~~~~

A special section ``environment`` defines environment variables that
will be propagated to all tests::

     [environment]
     CFLAGS=-O3
     PATH=%(testbase)s/bin:%(default_path)s

Note how ``PATH`` can be adjusted to include local scripts: the
example above prefixes it with a local ``bin/`` directory inside the
base directory, using the predefined ``default_path`` macro to refer
to the ``PATH`` as it is set by default.

Furthermore, by setting ``PATH`` to include the ``btest``
distribution directory, one could skip the installation of the
``btest`` package.

.. _alternative:

Alternatives
~~~~~~~~~~~~

BTest can run a set of tests with different settings than it would
normally use by specifying an *alternative* configuration. Currently,
three things can be adjusted:

    - Further environment variables can be set that will then be
      available to all the commands that a test executes.

    - *Filters* can modify an input file before a test uses it.

    - *Substitutions* can modify command lines executed as part of a
      test.

We discuss the three separately in the following. All of them are
defined by adding sections ``[<type>-<name>]`` where ``<type>``
corresponds to the type of adjustment being made and ``<name>`` is the
name of the alternative. Once at least one section is defined for a
name, that alternative can be enabled by BTest's ``--alternative``
flag.

Environment Variables
^^^^^^^^^^^^^^^^^^^^^

An alternative can add further environment variables by defining an
``[environment-<name>]`` section:

     [environment-myalternative]
     CFLAGS=-O3

Running ``btest`` with ``--alternative=myalternative`` will now make
the ``CFLAGS`` environment variable available to all commands
executed.

.. _filters:

Filters
^^^^^^^

Filters are a transparent way to adapt the input to a specific test
command before it is executed. A filter is defined by adding a section
``[filter-<name>]`` to the configuration file. This section must have
exactly one entry, and the name of that entry is interpreted as the
name of a command whose input is to be filtered.  The value of that
entry is the name of a filter script that will be run with two
arguments representing input and output files, respectively. Example::

    [filter-myalternative]
    cat=%(testbase)s/bin/filter-cat

Once the filter is activated by running ``btest`` with
``--alternative=myalternative``, every time a ``@TEST-EXEC: cat
%INPUT`` is found, ``btest`` will first execute (something similar to)
``%(testbase)s/bin/filter-cat %INPUT out.tmp``, and then subsequently
``cat out.tmp`` (i.e., the original command but with the filtered
output).  In the simplest case, the filter could be a no-op in the
form ``cp $1 $2``.

.. note::
    There are a few limitations to the filter concept currently:

    * Filters are *always* fed with ``%INPUT`` as their first
      argument. We should add a way to filter other files as well.

    * Filtered commands are only recognized if they are directly
      starting the command line. For example, ``@TEST-EXEC: ls | cat
      >outout`` would not trigger the example filter above.

    * Filters are only executed for ``@TEST-EXEC``, not for
      ``@TEST-EXEC-FAIL``.

.. _substitution:

Substitutions
^^^^^^^^^^^^^^

Substitutions are similar to filters, yet they do not adapt the input
but the command line being executed. A substitution is defined by
adding a section ``[substitution-<name>]`` to the configuration file.
For each entry in this section, the entry's name specifies the
command that is to be replaced with something else given as its value.
Example::

    [substitution-myalternative]
    gcc=gcc -O2

Once the substitution is activated by running ``btest`` with
``--alternative=myalternative``, every time a ``@TEST-EXEC`` executes
``gcc``, that is replaced with ``gcc -O2``. The replacement is simple
string substitution so it works not only with commands but anything
found on the command line; it however only replaces full words, not
subparts of words.

Writing Tests
-------------

``btest`` scans a test file for lines containing keywords that
trigger certain functionality. Currently, the following keywords are
supported:

.. _@TEST-EXEC:

``@TEST-EXEC: <cmdline>``
    Executes the given command line and aborts the test if it
    returns an error code other than zero. The ``<cmdline>`` is
    passed to the shell and thus can be a pipeline, use redirection,
    and any environment variables specified in ``<cmdline>`` will be
    expanded, etc.

    When running a test, the current working directory for all
    command lines will be set to a temporary sandbox (and will be
    deleted later).

    There are two macros that can be used in ``<cmdline>``:
    ``%INPUT`` will be replaced with the full pathname of the file defining
    the test; and ``%DIR`` will be replaced with the directory where
    the test file is located. The latter can be used to reference
    further files also located there.

    In addition to environment variables defined in the
    configuration file, there are further ones that are passed into
    the commands:

        ``TEST_DIAGNOSTICS``
            A file where further diagnostic information can be saved
            in case a command fails. ``--diagnostics`` will show
            this file. (This is also where ``btest-diff`` stores its
            diff.)

        ``TEST_MODE``
            This is normally set to ``TEST``, but will be ``UPDATE``
            if ``btest`` is run with ``--update-baseline``, or
            ``UPDATE_INTERACTIVE`` if run with ``--update-interactive``.

        ``TEST_BASELINE``
            The name of a directory where the command can save permanent
            information across ``btest`` runs. (This is where
            ``btest-diff`` stores its baseline in ``UPDATE`` mode.)

        ``TEST_NAME``
            The name of the currently executing test.

        ``TEST_VERBOSE``
            The path of a file where the test can record further
            information about its execution that will be included with
            btest's ``--verbose`` output. This is for further tracking
            the execution of commands and should generally generate
            output that follows a line-based structure.

    .. note::

        If a command returns the special exit code 100, the test is
        considered failed, however subsequent test commands are still
        run. ``btest-diff`` uses this special exit code to indicate that
        no baseline has yet been established.

        If a command returns the special exit code 200, the test is
        considered failed and all further test executions are aborted.


``@TEST-EXEC-FAIL: <cmdline>``
    Like ``@TEST-EXEC``, except that this expects the command to
    *fail*, i.e., the test is aborted when the return code is zero.

``@TEST-REQUIRES: <cmdline>``
    Defines a condition that must be met for the test to be executed.
    The given command line will be run before any of the actual test
    commands, and it must return success for the test to continue. If
    it does not return success, the rest of the test will be skipped
    but doing so will not be considered a failure of the test. This allows to
    write conditional tests that may not always make sense to run, depending
    on whether external constraints are satisfied or not (say, whether
    a particular library is available). Multiple requirements may be
    specified and then all must be met for the test to continue.

``@TEST-ALTERNATIVE: <alternative>`` Runs this test only for the given
   alternative (see alternative_). If ``<alternatives>`` is
   ``default``, the test executes when BTest runs with no alternative
   given (which however is the default anyways).

``@TEST-NOT-ALTERNATIVE: <alternative>`` Ignores this test for the
   given alternative (see alternative_).  If ``<alternative>`` is
   ``default``, the test is ignored if BTest runs with no alternative
   given.

``@TEST-COPY-FILE: <file>``
    Copy the given file into the test's directory before the test is
    run. If ``<file>`` is a relative path, it's interpreted relative
    to the BTest's base directory. Environment variables in ``<file>``
    will be replaced if enclosed in ``${..}``. This command can be
    given multiple times.

``@TEST-START-NEXT``
    This is a short-cut for defining multiple test inputs in the
    same file, all executing with the same command lines. When
    ``@TEST-START-NEXT`` is encountered, the test file is initially
    considered to end at that point, and all ``@TEST-EXEC-*`` are
    run with an ``%INPUT`` truncated accordingly. Afterwards, a
    *new* ``%INPUT`` is created with everything *following* the
    ``@TEST-START-NEXT`` marker, and the *same* commands are run
    again (further ``@TEST-EXEC-*`` will be ignored). The effect is
    that a single file can actually define two tests, and the
    ``btest`` output will enumerate them::

        > cat examples/t5.sh
        # @TEST-EXEC: cat %INPUT | wc -c >output
        # @TEST-EXEC: btest-diff output

        This is the first test input in this file.

        # @TEST-START-NEXT

        ... and the second.

        > ./btest -D examples/t5.sh
        examples.t5 ... ok
          % cat .diag
          == File ===============================
          119
          [...]

        examples.t5-2 ... ok
          % cat .diag
          == File ===============================
          22
          [...]

    Multiple ``@TEST-START-NEXT`` can be used to create more than
    two tests per file.

``@TEST-START-FILE <file>``
    This is used to include an additional input file for a test
    right inside the test file. All lines following the keyword will
    be written into the given file (and removed from the test's
    `%INPUT`) until a terminating ``@TEST-END-FILE`` is found.
    Example::

        > cat examples/t6.sh
        # @TEST-EXEC: awk -f %INPUT <foo.dat >output
        # @TEST-EXEC: btest-diff output

            { lines += 1; }
        END { print lines; }

        @TEST-START-FILE foo.dat
        1
        2
        3
        @TEST-END-FILE

        > btest -D examples/t6.sh
        examples.t6 ... ok
          % cat .diag
          == File ===============================
          3

    Multiple such files can be defined within a single test.

    Note that this is only one way to use further input files.
    Another is to store a file in the same directory as the test
    itself, making sure it's ignored via ``IgnoreFiles``, and then
    refer to it via ``%DIR/<name>``.

.. _@TEST-GROUP:

``@TEST-GROUP: <group>``
    Assigns the test to a group of name ``<group>``. By using option
    ``-g`` one can limit execution to all tests that belong to a given
    group (or a set of groups).

.. _@TEST-SERIALIZE:

``@TEST-SERIALIZE: <set>``
   When using option ``-j`` to parallelize execution, all tests that
   specify the same serialization set are guaranteed to run
   sequentially. ``<set>`` is an arbitrary user-chosen string.


Canonifying Diffs
=================

``btest-diff`` has the capability to filter its input through an
additional script before it compares the current version with the
baseline. This can be useful if certain elements in an output are
*expected* to change (e.g., timestamps). The filter can then
remove/replace these with something consistent. To enable such
canonification, set the environment variable
``TEST_DIFF_CANONIFIER`` to a script reading the original version
from stdin and writing the canonified version to stdout. Note that
both baseline and current output are passed through the filter
before their differences are computed.

Running Processes in the Background
===================================

Sometimes processes need to be spawned in the background for a test,
in particular if multiple processes need to cooperate in some fashion.
``btest`` comes with two helper scripts to make life easier in such a
situation:

``btest-bg-run <tag> <cmdline>``
    This is a script that runs ``<cmdline>`` in the background, i.e.,
    it's like using ``cmdline &`` in a shell script. Test execution
    continues immediately with the next command. Note that the spawned
    command is *not* run in the current directory, but instead in a
    newly created sub-directory called ``<tag>``. This allows
    spawning multiple instances of the same process without needing to
    worry about conflicting outputs. If you want to access a command's
    output later, like with ``btest-diff``, use ``<tag>/foo.log`` to
    access it.

``btest-bg-wait [-k] <timeout>``
    This script waits for all processes previously spawned via
    ``btest-bg-run`` to finish. If any of them exits with a non-zero
    return code, ``btest-bg-wait`` does so as well, indicating a
    failed test. ``<timeout>`` is mandatory and gives the maximum
    number of seconds to wait for any of the processes to terminate.
    If any process hasn't done so when the timeout expires, it will be
    killed and the test is considered to be failed as long as ``-k``
    is not given. If ``-k`` is given, pending processes are still
    killed but the test continues normally, i.e., non-termination is
    not considered a failure in this case. This script also collects
    the processes' stdout and stderr outputs for diagnostics output.

Integration with Sphinx
=======================

``btest`` comes with a new directive for the documentation framework
`Sphinx <http://sphinx.pocoo.org>`_. The directive allows to write a
test directly inside a Sphinx document, and then to include output
from the test's command into the generated documentation. The same
tests can also run externally and will catch if any changes to the
included content occur. The following walks through setting this up.

Configuration
-------------

First, you need to tell Sphinx a base directory for the ``btest``
configuration as well as a directory in there where to store tests
it extracts from the Sphinx documentation. Typically, you'd just
create a new subdirectory ``tests`` in the Sphinx project for the
``btest`` setup and then store the tests in there in, e.g.,
``doc/``::

    cd <sphinx-root>
    mkdir tests
    mkdir tests/doc

Then add the following to your Sphinx ``conf.py``::

    extensions += ["btest-sphinx"]
    btest_base="tests"         # Relative to Sphinx-root.
    btest_tests="doc"          # Relative to btest_base.

Next, a finalizer to ``btest.cfg``::

    [btest]
    ...
    Finalizer=btest-diff-rst

Finally, create a ``btest.cfg`` in ``tests/`` as usual and add
``doc/`` to the ``TestDirs`` option.

Including a Test into a Sphinx Document
---------------------------------------

The ``btest`` extension provides a new directive to include a test
inside a Sphinx document::


    .. btest:: <test-name>

        <test content>

Here, ``<test-name>`` is a custom name for the test; it will be
stored in ``btest_tests`` under that name. ``<test content>`` is just
a standard test as you would normally put into one of the
``TestDirs``. Example::


    .. btest:: just-a-test

        @TEST-EXEC: expr 2 + 2

When you now run Sphinx, it will (1) store the test content into
``tests/doc/just-a-test`` (assuming the above path layout), and (2)
execute the test by running ``btest`` on it. You can then run
``btest`` manually in ``tests/`` as well and it will execute the test
just as it would in a standard setup. If a test fails when Sphinx runs
it, there will be a corresponding error and include the diagnostic output
into the document.

By default, nothing else will be included into the generated
documentation, i.e., the above test will just turn into an empty text
block. However, ``btest`` comes with a set of scripts that you can use
to specify content to be included. As a simple example,
``btest-rst-cmd <cmdline>`` will execute a command and (if it
succeeds) include both the command line and the standard output into
the documentation. Example::

    .. btest:: another-test

        @TEST-EXEC: btest-rst-cmd echo Hello, world!

When running Sphinx, this will render as:

.. code::

    # echo Hello, world!
    Hello world!


When running ``btest`` manually in ``tests/``, the ``Finalizer`` we
added to ``btest.cfg`` (see above) compares the generated reST code
with a previously established baseline, just like ``btest-diff`` does
with files. To establish the initial baseline, run ``btest -u``, like
you would with ``btest-diff``.

Scripts
-------

The following Sphinx support scripts come with ``btest``:

``btest-rst-cmd [options] <cmdline>``

    By default, this executes ``<cmdline>`` and includes both the
    command line itself and its standard output into the generated
    documentation. See above for an example.

    This script provides the following options:

        -c ALTERNATIVE_CMDLINE
            Show ``ALTERNATIVE_CMDLINE`` in the generated
            documentation instead of the one actually executed. (It
            still runs the ``<cmdline>`` given outside the option.)

        -d
            Do not actually execute ``<cmdline>``; just format it for
            the generated documentation and include no further output.

        -f FILTER_CMD
            Pipe the command line's output through ``FILTER_CMD``
            before including. If ``-r`` is given, it filters the
            file's content instead of stdout.

        -o
            Do not include the executed command into the generated
            documentation, just its output.

        -r FILE
            Insert ``FILE`` into output instead of stdout.


``btest-rst-include <file>``

    Includes ``<file>`` inside a code block.

``btest-rst-pipe <cmdline>``

    Executes ``<cmdline>``, includes its standard output inside a code
    block. Note that this script does not include the command line
    itself into the code block, just the output.

.. note::

    All these scripts can be run directly from the command line to show
    the reST code they generate.

.. note::

    ``btest-rst-cmd`` can do everything the other scripts provide if
    you give it the right options. In fact, the other scripts are
    provided just for convenience and leverage ``btest-rst-cmd``
    internally.

License
=======

btest is open-source under a BSD licence.

