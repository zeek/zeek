
===================
Writing Bro Plugins
===================

Bro is internally moving to a plugin structure that enables extending
the system dynamically, without modifying the core code base. That way
custom code remains self-contained and can be maintained, compiled,
and installed independently. Currently, plugins can add the following
functionality to Bro:

    - Bro scripts.

    - Builtin functions/events/types for the scripting language.

    - Protocol analyzers.

    - File analyzers.

    - Packet sources and packet dumpers. TODO: Not yet.

    - Logging framework backends. TODO: Not yet.

    - Input framework readers. TODO: Not yet.

A plugin's functionality is available to the user just as if Bro had
the corresponding code built-in. Indeed, internally many of Bro's
pieces are structured as plugins as well, they are just statically
compiled into the binary rather than loaded dynamically at runtime.

Quick Start
===========

Writing a basic plugin is quite straight-forward as long as one
follows a few conventions. In the following we walk a simple example
plugin that adds a new built-in function (bif) to Bro: we'll add 
``rot13(s: string) : string``, a function that rotates every character
in a string by 13 places.

Generally, a plugin comes in the form of a directory following a
certain structure. To get started, Bro's distribution provides a
helper script ``aux/bro-aux/plugin-support/init-plugin`` that creates
a skeleton plugin that can then be customized. Let's use that::

    # mkdir rot13-plugin
    # cd rot13-plugin
    # init-plugin Demo Rot13

As you can see the script takes two arguments. The first is a
namespace the plugin will live in, and the second a descriptive name
for the plugin itself. Bro uses the combination of the two to identify
a plugin. The namespace serves to avoid naming conflicts between
plugins written by independent developers; pick, e.g., the name of
your organisation. The namespace ``Bro`` is reserved for functionality
distributed by the Bro Project. In our example, the plugin will be
called ``Demo::Rot13``.

The ``init-plugin`` script puts a number of files in place. The full
layout is described later. For now, all we need is
``src/rot13.bif``. It's initially empty, but we'll add our new bif
there as follows::

    # cat src/rot13.bif
    module CaesarCipher;

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
configure script put in place by ``init-plugin`` where the Bro source
tree is located (Bro needs to have been built there first)::

    # ./configure --bro-dist=/path/to/bro/dist && make
    [... cmake output ...]

Now our ``rot13-plugin`` directory has everything that it needs
for Bro to recognize it as a dynamic plugin. Once we point Bro to it,
it will pull it in automatically, as we can check with the ``-N``
option::

    # export BRO_PLUGIN_PATH=/path/to/rot13-plugin
    # bro -N
    [...]
    Plugin: Demo::Rot13 - <Insert brief description of plugin> (dynamic, version 1)
    [...]

That looks quite good, except for the dummy description that we should
replace with something nicer so that users will know what our plugin
is about.  We do this by editing the ``config.description`` line in
``src/Plugin.cc``, like this::

    [...]
    plugin::Configuration Configure()
        {
        plugin::Configuration config;
        config.name = "Demo::Rot13";
        config.description = "Caesar cipher rotating a string's characters by 13 places.";
        config.version.major = 1;
        config.version.minor = 0;
        return config;
        }
    [...]

    # make
    [...]
    # bro -N | grep Rot13
    Plugin: Demo::Rot13 - Caesar cipher rotating a string's characters by 13 places. (dynamic, version 1)

Better. Bro can also show us what exactly the plugin provides with the
more verbose option ``-NN``::

    # bro -NN
    [...]
    Plugin: Demo::Rot13 - Caesar cipher rotating a string's characters by 13 places. (dynamic, version 1)
        [Function] CaesarCipher::rot13
    [...]

There's our function. Now let's use it::

    # bro -e 'print CaesarCipher::rot13("Hello")'
    Uryyb

It works. We next install the plugin along with Bro itself, so that it
will find it directly without needing the ``BRO_PLUGIN_PATH``
environment variable. If we first unset the variable, the function
will no longer be available::

    # unset BRO_PLUGIN_PATH
    # bro -e 'print CaesarCipher::rot13("Hello")'
    error in <command line>, line 1: unknown identifier CaesarCipher::rot13, at or near "CaesarCipher::rot13"

Once we install it, it works again::

    # make install
    # bro -e 'print CaesarCipher::rot13("Hello")'
    Uryyb

The installed version went into
``<bro-install-prefix>/lib/bro/plugins/Demo_Rot13``.

We can distribute the plugin in either source or binary form by using
the Makefile's ``sdist`` and ``bdist`` target, respectively. Both
create corrsponding tarballs::

    # make sdist
    [...]
    Source distribution in build/sdist/Demo_Rot13.tar.gz

    # make bdist
    [...]
    Binary distribution in build/Demo_Rot13-darwin-x86_64.tar.gz

The source archive will contain everything in the plugin directory
except any generated files. The binary archive will contain anything
needed to install and run the plugin, i.e., just what ``make install``
puts into place as well. As the binary distribution is
platform-dependent, its name includes the OS and architecture the
plugin was built on.

Plugin Directory Layout
=======================

A plugin's directory needs to follow a set of conventions so that Bro
(1) recognizes it as a plugin, and (2) knows what to load.  While
``init-plugin`` takes care of most of this, the following is the full
story. We'll use ``<base>`` to represent a plugin's top-level
directory.

``<base>/__bro_plugin__``
    A file that marks a directory as containing a Bro plugin. The file
    must exist, and its content must consist of a single line with the
    qualified name of the plugin (e.g., "Demo::Rot13").

``<base>/lib/<plugin-name>-<os>-<arch>.so``
    The shared library containing the plugin's compiled code. Bro will
    load this in dynamically at run-time if OS and architecture match
    the current platform.

``scripts/``
    A directory with the plugin's custom Bro scripts. When the plugin
    gets activated, this directory will be automatically added to
    ``BROPATH``, so that any scripts/modules inside can be
    "@load"ed.

``scripts``/__load__.bro
    A Bro script that will be loaded immediately when the plugin gets
    activated. See below for more information on activating plugins.

``lib/bif/``
    Directory with auto-generated Bro scripts that declare the plugin's
    bif elements. The files here are produced by ``bifcl``.

By convention, a plugin should put its custom scripts into sub folders
of ``scripts/``, i.e., ``scripts/<script-namespace>/<script>.bro`` to
avoid conflicts. As usual, you can then put a ``__load__.bro`` in
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
as well as the ``__bro_plugin__`` magic file and the ``README`` (which
you should customize). One can add further CMake ``install`` rules to
install additional files if needed.

``init-plugin`` will never overwrite existing files, so it's safe to
rerun in an existing plugin directory; it only put files in place that
don't exist yet. That also provides a convenient way to revert a file
back to what ``init-plugin`` created originally: just delete it and
rerun.

Activating a Plugin
===================

A plugin needs to be *activated* to make it available to the user.
Activating a plugin will:

    1. Load the dynamic module
    2. Make any bif items available
    3. Add the ``scripts/`` directory to ``BROPATH``
    4. Load ``scripts/__load__.bro``

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

Plugin Component
================

The following gives additional information about providing individual
types of functionality via plugins. Note that a single plugin can
provide more than one type. For example, a plugin could provide
multiple protocol analyzers at once; or both a logging backend and
input reader at the same time.

We now walk briefly through the specifics of providing a specific type
of functionality (a *component*) through a plugin. We'll focus on
their interfaces to the plugin system, rather than specifics on
writing the corresponding logic (usually the best way to get going on
that is to start with an existing plugin providing a corresponding
component and adapt that). We'll also point out how the CMake
infrastructure put in place by the ``init-plugin`` helper script ties
the various pieces together.

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

Not yet available as plugins.

Input Reader
------------

Not yet available as plugins.

Packet Sources
--------------

Not yet available as plugins.

Packet Dumpers
--------------

Not yet available as plugins.

Hooks
=====

TODO.

Testing Plugins
===============

A plugin should come with a test suite to exercise its functionality.
The ``init-plugin`` script puts in place a basic </btest/README> setup
to start with. Initially, it comes with a single test that just checks
that Bro loads the plugin correctly. It won't have a baseline yet, so
let's get that in place::

    # cd tests
    # btest -d
    [  0%] plugin.loading ... failed
    % 'btest-diff output' failed unexpectedly (exit code 100)
    % cat .diag
    == File ===============================
    Demo::Rot13 - Caesar cipher rotating a string's characters by 13 places. (dynamic, version 1.0)
        [Function] CaesarCipher::rot13

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
    # cat >plugin/rot13.bro

    # @TEST-EXEC: bro %INPUT >output
    # @TEST-EXEC: btest-diff output

    event bro_init()
        {
        print CaesarCipher::rot13("Hello");
        }

Check the output::

    # btest -d plugin/rot13.bro
    [  0%] plugin.rot13 ... failed
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

    # btest -U plugin/rot13.bro
    all 1 tests successful

Run the test-suite::

    # btest
    all 2 tests successful

Debugging Plugins
=================

Plugins can use Bro's standard debug logger by using the
``PLUGIN_DBG_LOG(<plugin>, <args>)`` macro (defined in
``DebugLogger.h``), where ``<plugin>`` is the ``Plugin`` instance and
``<args>`` are printf-style arguments, just as with Bro's standard
debuggging macros.

At runtime, one then activates a plugin's debugging output with ``-B
plugin-<name>``, where ``<name>`` is the name of the plugin as
returned by its ``Configure()`` method, yet with the
namespace-separator ``::`` replaced with a simple dash. Example: If
the plugin is called ``Bro::Demo``, use ``-B plugin-Bro-Demo``. As
usual, the debugging output will be recorded to ``debug.log`` if Bro's
compiled in debug mode.


Documenting Plugins
===================

..todo::

    Integrate all this with Broxygen.



