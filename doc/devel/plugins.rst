
===================
Writing Bro Plugins
===================

Bro internally provides a plugin API that enables extending
the system dynamically, without modifying the core code base. That way
custom code remains self-contained and can be maintained, compiled,
and installed independently. Currently, plugins can add the following
functionality to Bro:

    - Bro scripts.

    - Builtin functions/events/types for the scripting language.

    - Protocol analyzers.

    - File analyzers.

    - Packet sources and packet dumpers.

    - Logging framework backends.

    - Input framework readers.

A plugin's functionality is available to the user just as if Bro had
the corresponding code built-in. Indeed, internally many of Bro's
pieces are structured as plugins as well, they are just statically
compiled into the binary rather than loaded dynamically at runtime.

Quick Start
===========

Writing a basic plugin is quite straight-forward as long as one
follows a few conventions. In the following we create a simple example
plugin that adds a new built-in function (bif) to Bro: we'll add 
``rot13(s: string) : string``, a function that rotates every character
in a string by 13 places.

Generally, a plugin comes in the form of a directory following a
certain structure. To get started, Bro's distribution provides a
helper script ``aux/bro-aux/plugin-support/init-plugin`` that creates
a skeleton plugin that can then be customized. Let's use that::

    # init-plugin ./rot13-plugin Demo Rot13

As you can see, the script takes three arguments. The first is a
directory inside which the plugin skeleton will be created.  The second
is the namespace the plugin will live in, and the third is a descriptive
name for the plugin itself relative to the namespace. Bro uses the
combination of namespace and name to identify a plugin. The namespace
serves to avoid naming conflicts between plugins written by independent
developers; pick, e.g., the name of your organisation. The namespace
``Bro`` is reserved for functionality distributed by the Bro Project. In
our example, the plugin will be called ``Demo::Rot13``.

The ``init-plugin`` script puts a number of files in place. The full
layout is described later. For now, all we need is
``src/rot13.bif``. It's initially empty, but we'll add our new bif
there as follows::

    # cat src/rot13.bif
    module Demo;

    function rot13%(s: string%) : string
        %{
        char* rot13 = copy_string(s->CheckString());

        for ( char* p = rot13; *p; p++ )
            {
            char b = islower(*p) ? 'a' : 'A';
            *p  = (*p - b + 13) % 26 + b;
            }

        BroString* bs = new BroString(1, reinterpret_cast<byte_vec>(rot13),
                                      strlen(rot13));
        return new StringVal(bs);
        %}

The syntax of this file is just like any other ``*.bif`` file; we
won't go into it here.

Now we can already compile our plugin, we just need to tell the
configure script (that ``init-plugin`` created) where the Bro
source tree is located (Bro needs to have been built there first)::

    # cd rot13-plugin
    # ./configure --bro-dist=/path/to/bro/dist && make
    [... cmake output ...]

This builds the plugin in a subdirectory ``build/``. In fact, that
subdirectory *becomes* the plugin: when ``make`` finishes, ``build/``
has everything it needs for Bro to recognize it as a dynamic plugin.

Let's try that. Once we point Bro to the ``build/`` directory, it will
pull in our new plugin automatically, as we can check with the ``-N``
option::

    # export BRO_PLUGIN_PATH=/path/to/rot13-plugin/build
    # bro -N
    [...]
    Demo::Rot13 - <Insert description> (dynamic, version 0.1)
    [...]

That looks quite good, except for the dummy description that we should
replace with something nicer so that users will know what our plugin
is about.  We do this by editing the ``config.description`` line in
``src/Plugin.cc``, like this::

    [...]
    plugin::Configuration Plugin::Configure()
        {
        plugin::Configuration config;
        config.name = "Demo::Rot13";
        config.description = "Caesar cipher rotating a string's characters by 13 places.";
        config.version.major = 0;
        config.version.minor = 1;
        return config;
        }
    [...]

Now rebuild and verify that the description is visible::

    # make
    [...]
    # bro -N | grep Rot13
    Demo::Rot13 - Caesar cipher rotating a string's characters by 13 places. (dynamic, version 0.1)

Bro can also show us what exactly the plugin provides with the
more verbose option ``-NN``::

    # bro -NN
    [...]
    Demo::Rot13 - Caesar cipher rotating a string's characters by 13 places. (dynamic, version 0.1)
        [Function] Demo::rot13
    [...]

There's our function. Now let's use it::

    # bro -e 'print Demo::rot13("Hello")'
    Uryyb

It works. We next install the plugin along with Bro itself, so that it
will find it directly without needing the ``BRO_PLUGIN_PATH``
environment variable. If we first unset the variable, the function
will no longer be available::

    # unset BRO_PLUGIN_PATH
    # bro -e 'print Demo::rot13("Hello")'
    error in <command line>, line 1: unknown identifier Demo::rot13, at or near "Demo::rot13"

Once we install it, it works again::

    # make install
    # bro -e 'print Demo::rot13("Hello")'
    Uryyb

The installed version went into
``<bro-install-prefix>/lib/bro/plugins/Demo_Rot13``.

One can distribute the plugin independently of Bro for others to use.
To distribute in source form, just remove the ``build/`` directory
(``make distclean`` does that) and then tar up the whole ``rot13-plugin/``
directory. Others then follow the same process as above after
unpacking.

To distribute the plugin in binary form, the build process
conveniently creates a corresponding tarball in ``build/dist/``. In
this case, it's called ``Demo_Rot13-0.1.tar.gz``, with the version
number coming out of the ``VERSION`` file that ``init-plugin`` put
into place. The binary tarball has everything needed to run the
plugin, but no further source files. Optionally, one can include
further files by specifying them in the plugin's ``CMakeLists.txt``
through the ``bro_plugin_dist_files`` macro; the skeleton does that
for ``README``, ``VERSION``, ``CHANGES``, and ``COPYING``. To use the
plugin through the binary tarball, just unpack it into
``<bro-install-prefix>/lib/bro/plugins/``.  Alternatively, if you unpack
it in another location, then you need to point ``BRO_PLUGIN_PATH`` there.

Before distributing your plugin, you should edit some of the meta
files that ``init-plugin`` puts in place. Edit ``README`` and
``VERSION``, and update ``CHANGES`` when you make changes. Also put a
license file in place as ``COPYING``; if BSD is fine, you will find a
template in ``COPYING.edit-me``.

Plugin Directory Layout
=======================

A plugin's directory needs to follow a set of conventions so that Bro
(1) recognizes it as a plugin, and (2) knows what to load.  While
``init-plugin`` takes care of most of this, the following is the full
story. We'll use ``<base>`` to represent a plugin's top-level
directory. With the skeleton, ``<base>`` corresponds to ``build/``.

``<base>/__bro_plugin__``
    A file that marks a directory as containing a Bro plugin. The file
    must exist, and its content must consist of a single line with the
    qualified name of the plugin (e.g., "Demo::Rot13").

``<base>/lib/<plugin-name>.<os>-<arch>.so``
    The shared library containing the plugin's compiled code. Bro will
    load this in dynamically at run-time if OS and architecture match
    the current platform.

``scripts/``
    A directory with the plugin's custom Bro scripts. When the plugin
    gets activated, this directory will be automatically added to
    ``BROPATH``, so that any scripts/modules inside can be
    "@load"ed.

``scripts``/__load__.bro
    A Bro script that will be loaded when the plugin gets activated.
    When this script executes, any BiF elements that the plugin
    defines will already be available. See below for more information
    on activating plugins.

``scripts``/__preload__.bro
    A Bro script that will be loaded when the plugin gets activated,
    but before any BiF elements become available. See below for more
    information on activating plugins.

``lib/bif/``
    Directory with auto-generated Bro scripts that declare the plugin's
    bif elements. The files here are produced by ``bifcl``.

Any other files in ``<base>`` are ignored by Bro.

By convention, a plugin should put its custom scripts into sub folders
of ``scripts/``, i.e., ``scripts/<plugin-namespace>/<plugin-name>/<script>.bro``
to avoid conflicts. As usual, you can then put a ``__load__.bro`` in
there as well so that, e.g., ``@load Demo/Rot13`` could load a whole
module in the form of multiple individual scripts.

Note that in addition to the paths above, the ``init-plugin`` helper
puts some more files and directories in place that help with
development and installation (e.g., ``CMakeLists.txt``, ``Makefile``,
and source code in ``src/``). However, all these do not have a special
meaning for Bro at runtime and aren't necessary for a plugin to
function.

``init-plugin``
===============

``init-plugin`` puts a basic plugin structure in place that follows
the above layout and augments it with a CMake build and installation
system. Plugins with this structure can be used both directly out of
their source directory (after ``make`` and setting Bro's
``BRO_PLUGIN_PATH``), and when installed alongside Bro (after ``make
install``).

``make install`` copies over the ``lib`` and ``scripts`` directories,
as well as the ``__bro_plugin__`` magic file and any further
distribution files specified in ``CMakeLists.txt`` (e.g., README,
VERSION). You can find a full list of files installed in
``build/MANIFEST``. Behind the scenes, ``make install`` really just
unpacks the binary tarball from ``build/dist`` into the destination
directory.

``init-plugin`` will never overwrite existing files. If its target
directory already exists, it will by default decline to do anything.
You can run it with ``-u`` instead to update an existing plugin,
however it will never overwrite any existing files; it will only put
in place files it doesn't find yet. To revert a file back to what
``init-plugin`` created originally, delete it first and then rerun
with ``-u``.

``init-plugin`` puts a ``configure`` script in place that wraps
``cmake`` with a more familiar configure-style configuration. By
default, the script provides two options for specifying paths to the
Bro source (``--bro-dist``) and to the plugin's installation directory
(``--install-root``). To extend ``configure`` with plugin-specific
options (such as search paths for its dependencies) don't edit the
script directly but instead extend ``configure.plugin``, which
``configure`` includes. That way you will be able to more easily
update ``configure`` in the future when the distribution version
changes. In ``configure.plugin`` you can use the predefined shell
function ``append_cache_entry`` to seed values into the CMake cache;
see the installed skeleton version and existing plugins for examples.

Activating a Plugin
===================

A plugin needs to be *activated* to make it available to the user.
Activating a plugin will:

    1. Load the dynamic module
    2. Make any bif items available
    3. Add the ``scripts/`` directory to ``BROPATH``
    4. Load ``scripts/__preload__.bro``
    5. Make BiF elements available to scripts.
    6. Load ``scripts/__load__.bro``

By default, Bro will automatically activate all dynamic plugins found
in its search path ``BRO_PLUGIN_PATH``. However, in bare mode (``bro
-b``), no dynamic plugins will be activated by default; instead the
user can selectively enable individual plugins in scriptland using the
``@load-plugin <qualified-plugin-name>`` directive (e.g.,
``@load-plugin Demo::Rot13``). Alternatively, one can activate a
plugin from the command-line by specifying its full name
(``Demo::Rot13``), or set the environment variable
``BRO_PLUGIN_ACTIVATE`` to a list of comma(!)-separated names of
plugins to unconditionally activate, even in bare mode.

``bro -N`` shows activated plugins separately from found but not yet
activated plugins. Note that plugins compiled statically into Bro are
always activated, and hence show up as such even in bare mode.

Plugin Components
=================

The following subsections detail providing individual types of
functionality via plugins. Note that a single plugin can provide more
than one component type. For example, a plugin could provide multiple
protocol analyzers at once; or both a logging backend and input reader
at the same time.

.. todo::

    These subsections are mostly missing right now, as much of their
    content isn't actually plugin-specific, but concerns generally
    writing such functionality for Bro. The best way to get started
    right now is to look at existing code implementing similar
    functionality, either as a plugin or inside Bro proper. Also, for
    each component type there's a unit test in
    ``testing/btest/plugins`` creating a basic plugin skeleton with a
    corresponding component.

Bro Scripts
-----------

Scripts are easy: just put them into ``scripts/``, as described above.
The CMake infrastructure will automatically install them, as well
include them into the source and binary plugin distributions.

Builtin Language Elements
-------------------------

Functions
    TODO

Events
    TODO

Types
    TODO

Protocol Analyzers
------------------

TODO.

File Analyzers
--------------

TODO.

Logging Writer
--------------

TODO.

Input Reader
------------

TODO.

Packet Sources
--------------

TODO.

Packet Dumpers
--------------

TODO.

Hooks
=====

TODO.

Testing Plugins
===============

A plugin should come with a test suite to exercise its functionality.
The ``init-plugin`` script puts in place a basic
:doc:`BTest <../../components/btest/README>` setup
to start with. Initially, it comes with a single test that just checks
that Bro loads the plugin correctly. It won't have a baseline yet, so
let's get that in place::

    # cd tests
    # btest -d
    [  0%] rot13.show-plugin ... failed
    % 'btest-diff output' failed unexpectedly (exit code 100)
    % cat .diag
    == File ===============================
    Demo::Rot13 - Caesar cipher rotating a string's characters by 13 places. (dynamic, version 0.1)
        [Function] Demo::rot13

    == Error ===============================
    test-diff: no baseline found.
    =======================================

    # btest -U
    all 1 tests successful

    # cd ..
    # make test
    make -C tests
    make[1]: Entering directory `tests'
    all 1 tests successful
    make[1]: Leaving directory `tests'

Now let's add a custom test that ensures that our bif works
correctly::

    # cd tests
    # cat >rot13/bif-rot13.bro

    # @TEST-EXEC: bro %INPUT >output
    # @TEST-EXEC: btest-diff output

    event bro_init()
        {
        print Demo::rot13("Hello");
        }

Check the output::

    # btest -d rot13/bif-rot13.bro
    [  0%] rot13.bif-rot13 ... failed
    % 'btest-diff output' failed unexpectedly (exit code 100)
    % cat .diag
    == File ===============================
    Uryyb
    == Error ===============================
    test-diff: no baseline found.
    =======================================

    % cat .stderr

    1 of 1 test failed

Install the baseline::

    # btest -U rot13/bif-rot13.bro
    all 1 tests successful

Run the test-suite::

    # btest
    all 2 tests successful

Debugging Plugins
=================

If your plugin isn't loading as expected, Bro's debugging facilities
can help illuminate what's going on. To enable, recompile Bro
with debugging support (``./configure --enable-debug``), and
afterwards rebuild your plugin as well. If you then run Bro with ``-B
plugins``, it will produce a file ``debug.log`` that records details
about the process for searching, loading, and activating plugins. 

To generate your own debugging output from inside your plugin, you can
add a custom debug stream by using the ``PLUGIN_DBG_LOG(<plugin>,
<args>)`` macro (defined in ``DebugLogger.h``), where ``<plugin>`` is
the ``Plugin`` instance and ``<args>`` are printf-style arguments,
just as with Bro's standard debugging macros (grep for ``DBG_LOG`` in
Bro's ``src/`` to see examples). At runtime, you can then activate
your plugin's debugging output with ``-B plugin-<name>``, where
``<name>`` is the name of the plugin as returned by its
``Configure()`` method, yet with the namespace-separator ``::``
replaced with a simple dash. Example: If the plugin is called
``Demo::Rot13``, use ``-B plugin-Demo-Rot13``. As usual, the debugging
output will be recorded to ``debug.log`` if Bro's compiled in debug
mode.

Documenting Plugins
===================

.. todo::

    Integrate all this with Broxygen.



