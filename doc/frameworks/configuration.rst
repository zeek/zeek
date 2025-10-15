
.. _framework-configuration:

=======================
Configuration Framework
=======================

Zeek includes a configuration framework that allows updating script options at
runtime. This functionality consists of an :zeek:see:`option` declaration in
the Zeek language, configuration files that enable changing the value of
options at runtime, option-change callbacks to process updates in your Zeek
scripts, a couple of script-level functions to manage config settings directly,
and a log file (:file:`config.log`) that contains information about every
option value change according to :zeek:see:`Config::Info`.

Introduction
============

The configuration framework provides an alternative to using Zeek script
constants to store various Zeek settings.

While traditional constants work well when a value is not expected to change at
runtime, they cannot be used for values that need to be modified occasionally.
While a :zeek:see:`redef` allows a re-definition of an already defined constant
in Zeek, these redefinitions can only be performed when Zeek first starts.
Afterwards, constants can no longer be modified.

However, it is clearly desirable to be able to change at runtime many of the
configuration options that Zeek offers. Restarting Zeek can be time-consuming
and causes it to lose all connection state and knowledge that it accumulated.
Zeek’s configuration framework solves this problem.

Declaring Options
=================

The :zeek:see:`option` keyword allows variables to be declared as configuration
options:

.. code-block:: zeek

  module Test;

  export {
      option my_networks: set[subnet] = {};
      option enable_feature = F;
      option hostname = "testsystem";
      option timeout_after = 1min;
      option my_ports: vector of port = {};
  }

Options combine aspects of global variables and constants. Like global
variables, options cannot be declared inside a function, hook, or event
handler. Like constants, options must be initialized when declared (the type
can often be inferred from the initializer but may need to be specified when
ambiguous). The value of an option can change at runtime, but options cannot be
assigned a new value using normal assignments.

The initial value of an option can be redefined with a :zeek:see:`redef`
declaration just like for global variables and constants. However, there is no
need to specify the :zeek:see:`&redef` attribute in the declaration of an
option. For example, given the above option declarations, here are possible
redefs that work anyway:

.. code-block:: zeek

  redef Test::enable_feature = T;
  redef Test::my_networks += { 10.1.0.0/16, 10.2.0.0/16 };

Changing Options
================

The configuration framework facilitates reading in new option values from
external files at runtime. Configuration files contain a mapping between option
names and their values. Each line contains one option assignment, formatted as
follows::

  [option name][tab/spaces][new value]

Lines starting with ``#`` are comments and ignored.

You register configuration files by adding them to
:zeek:see:`Config::config_files`, a set of filenames. Simply say something like
the following in :file:`local.zeek`:

.. code-block:: zeek

  redef Config::config_files += { "/path/to/config.dat" };

Zeek will then monitor the specified file continuously for changes. For
example, editing a line containing::

  Test::enable_feature T

to the config file while Zeek is running will cause it to automatically update
the option’s value in the scripting layer. The next time your code accesses the
option, it will see the new value.

.. note::

  The config framework is clusterized. In a cluster configuration, only the
  manager node watches the specified configuration files, and relays option
  updates across the cluster.

Config File Formatting
----------------------

The formatting of config option values in the config file is not the same as in
Zeek’s scripting language. Keep an eye on the :file:`reporter.log` for warnings
from the config reader in case of incorrectly formatted values, which it’ll
generally ignore when encountered. The following table summarizes supported
types and their value representations:

.. list-table::
  :header-rows: 1

  * - Data Type
    - Sample Config File Entry
    - Comments

  * - :zeek:see:`addr`
    - ``1.2.3.4``
    - Plain IPv4 or IPv6 address, as in Zeek. No ``/32`` or similar netmasks.

  * - :zeek:see:`bool`
    - ``T``
    - ``T`` or ``1`` for true, ``F`` or ``0`` for false

  * - :zeek:see:`count`
    - ``42``
    - Plain, nonnegative integer.

  * - :zeek:see:`double`
    - ``-42.5``
    - Plain double number.

  * - :zeek:see:`enum`
    - ``Enum::FOO_A``
    - Plain enum string.

  * - :zeek:see:`int`
    - ``-1``
    - Plain integer.

  * - :zeek:see:`interval`
    - ``3600.0``
    - Always in epoch seconds, with optional fraction of seconds. Never
      includes a time unit.

  * - :zeek:see:`pattern`
    - ``/(foo|bar)/``
    - The regex pattern, within forward-slash characters.

  * - :zeek:see:`port`
    - ``42/tcp``
    - Port number with protocol, as in Zeek. When the protocol part is missing,
      Zeek interprets it as ``/unknown``.

  * - :zeek:see:`set`
    - ``80/tcp,53/udp``
    - The set members, formatted as per their own type, separated by commas.
      For an empty set, use an empty string: just follow the option name with
      whitespace.

      Sets with multiple index types (e.g. ``set[addr,string]``) are currently
      not supported in config files.

  * - :zeek:see:`string`
    - ``Don’t bite, Zeek``
    - Plain string, no quotation marks. Given quotation marks become part of
      the string. Everything after the whitespace separator delineating the
      option name becomes the string. Saces and special characters are fine.
      Backslash characters (e.g. ``\n``) have no special meaning.

  * - :zeek:see:`subnet`
    - ``1.2.3.4/16``
    - Plain subnet, as in Zeek.

  * - :zeek:see:`time`
    - ``1608164505.5``
    - Always in epoch seconds, with optional fraction of seconds. Never
      includes a time unit.

  * - :zeek:see:`vector`
    - ``1,2,3,4``
    - The set members, formatted as per their own type, separated by commas.
      For an empty vector, use an empty string: just follow the option name
      with whitespace.

This leaves a few data types unsupported, notably tables and records. If you
require these, build up an instance of the corresponding type manually (perhaps
from a separate input framework file) and then call
:zeek:see:`Config::set_value` to update the option:

.. code-block:: zeek

  module Test;

  export {
      option host_port: table[addr] of port = {};
  }

  event zeek_init() {
      local t: table[addr] of port = { [10.0.0.2] = 123/tcp };
      Config::set_value("Test::host_port", t);
  }


Regardless of whether an option change is triggered by a config file or via
explicit :zeek:see:`Config::set_value` calls, Zeek always logs the change to
:file:`config.log`. A sample entry::

  #fields ts      id      old_value       new_value       location
  #types  time    string  string  string  string
  1608167352.498872      Test::a_count     42      3      config.txt

Mentioning options repeatedly in the config files leads to multiple update
events; the last entry “wins”. Mentioning options that do not correspond to
existing options in the script layer is safe, but triggers warnings in
:file:`reporter.log`::

  warning: config.txt/Input::READER_CONFIG: Option 'an_unknown' does not exist. Ignoring line.

Internally, the framework uses the Zeek input framework to learn about config
changes. If you inspect the configuration framework scripts, you will notice
that the scripts simply catch input framework events and call
:zeek:see:`Config::set_value` to set the relevant option to the new value. If
you want to change an option in your scripts at runtime, you can likewise call
:zeek:see:`Config::set_value` directly from a script (in a cluster
configuration, this only needs to happen on the manager, as the change will be
automatically sent to all other nodes in the cluster).

.. note::

  The input framework is usually very strict about the syntax of input files, but
  that is not the case for configuration files. These require no header lines,
  and both tabs and spaces are accepted as separators. A custom input reader,
  specifically for reading config files, facilitates this.

.. tip::

  The gory details of option-parsing reside in ``Ascii::ParseValue()`` in
  :file:`src/threading/formatters/Ascii.cc` and ``Value::ValueToVal`` in
  :file:`src/threading/SerialTypes.cc` in the Zeek core.

Change Handlers
===============

A change handler is a user-defined function that Zeek calls each time an option
value changes. This allows you to react programmatically to option changes. The
following example shows how to register a change handler for an option that has
a data type of :zeek:see:`addr` (for other data types, the return type and
second parameter data type must be adjusted accordingly):

.. code-block:: zeek

  module Test;

  export {
      option testaddr = 127.0.0.1;
  }

  # Note: the data type of 2nd parameter and return type must match
  function change_addr(id: string, new_value: addr): addr
      {
      print fmt("Value of %s changed from %s to %s", id, testaddr, new_value);
      return new_value;
      }

  event zeek_init()
      {
      Option::set_change_handler("Test::testaddr", change_addr);
      }

Immediately before Zeek changes the specified option value, it invokes any
registered change handlers. The value returned by the change handler is the
value Zeek assigns to the option.  This allows, for example, checking of values
to reject invalid input (the original value can be returned to override the
change).

.. note::

  :zeek:see:`Option::set_change_handler` expects the name of the option to
  invoke the change handler for, not the option itself. Also, that name
  includes the module name, even when registering from within the module.

It is possible to define multiple change handlers for a single option. In this
case, the change handlers are chained together: the value returned by the first
change handler is the “new value” seen by the next change handler, and so on.
The built-in function :zeek:see:`Option::set_change_handler` takes an optional
third argument that can specify a priority for the handlers.

A change handler function can optionally have a third argument of type string.
When a config file triggers a change, then the third argument is the pathname
of the config file. When the :zeek:see:`Config::set_value` function triggers a
change, then the third argument of the change handler is the value passed to
the optional third argument of the :zeek:see:`Config::set_value` function.

.. tip::

  Change handlers are also used internally by the configuration framework. If
  you look at the script-level source code of the config framework, you can see
  that change handlers log the option changes to :file:`config.log`.

When Change Handlers Trigger
----------------------------

Change handlers often implement logic that manages additional internal state.
For example, depending on a performance toggle option, you might initialize or
clean up a caching structure. In such scenarios you need to know exactly when
and whether a handler gets invoked. The following hold:

* When no config files get registered in :zeek:see:`Config::config_files`,
  change handlers do not run.
* When none of any registered config files exist on disk, change handlers do
  not run.

That is, change handlers are tied to config files, and don’t automatically run
with the option’s default values.

* When a config file exists on disk at Zeek startup, change handlers run with
  the file’s config values.
* When the config file contains the same value the option already defaults to,
  its change handlers are invoked anyway.
* :zeek:see:`zeek_init` handlers run before any change handlers — i.e., they
  run with the options’ default values.
* Since the config framework relies on the input framework, the input
  framework’s inherent asynchrony applies: you can’t assume when exactly an
  option change manifests in the code.

If your change handler needs to run consistently at startup and when options
change, you can call the handler manually from :zeek:see:`zeek_init` when you
register it. That way, initialization code always runs for the option’s default
value, and also for any new values.

.. code-block:: zeek

  module Test;

  export {
      option use_cache = T;
  }

  function use_cache_hdlr(id: string, new_value: bool): bool
      {
      if ( new_value ) {
          # Ensure caching structures are set up properly
      }

      return new_value;
      }

  event zeek_init()
      {
      use_cache_hdlr("Test::use_cache", use_cache);
      Option::set_change_handler("Test::use_cache", use_cache_hdlr);
      }
