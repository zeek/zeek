
.. _framework-configuration:

=======================
Configuration Framework
=======================

.. rst-class:: opening

Bro includes a "configuration framework" that allows
updating script options dynamically at runtime. This functionality
consists of several components: an "option" declaration, the
ability to specify input files to enable changing the value of options at
runtime, a couple of functions, and a log file "config.log"
which contains information about every change to option values.


.. contents::


Introduction
------------

The configuration framework provides an alternative to using Bro
script constants to store various Bro settings.

In general, traditional constants can be used when a value is not
expected to change at runtime, but they cannot be used for values that
need to be modified occasionally. While a "redef" allows a
re-definition of an already defined constant in Bro, these
redefinitions can only be performed when Bro first starts. Afterwards,
constants can no longer be modified.

However, it is clearly desirable to be able to change at runtime many
of the configuration options that Bro offers. Having to restart Bro
can be time-consuming and causes Bro to lose all connection state and
knowledge that it accumulated. Bro's configuration framework solves
this problem by allowing changing configuration options at runtime.

Declaring options
-----------------

The "option" keyword allows variables to be declared as configuration options.

.. code:: bro

    module TestModule;

    export {
        option my_networks: set[subnet] = {};
        option enable_feature = F;
        option hostname = "testsystem";
        option timeout = 1min;
        option my_ports: vector of port = {};
    }

The rules regarding options can be thought of as being in between global
variables and constants.  Like global variables, options cannot be declared
inside a function, hook, or event handler.  Like constants, options must be
initialized when declared (the type can often be inferred from the initializer
but may need to be specified).  The value of an option can change at runtime,
but options cannot be assigned a new value using normal assignments.

The initial value of an option can be redefined with a :bro:keyword:`redef`
declaration just like for global variables and constants.  The only difference
being that there is no need to specify the :bro:attr:`&redef` attribute in
the declaration of an option.  For example, given the above option
declarations, here are some possible redefs:

.. code:: bro

    redef TestModule::enable_feature = T;
    redef TestModule::my_networks += { 10.1.0.0/16, 10.2.0.0/16 };


Changing options
----------------

The configuration framework facilitates reading in new option values
from external files at runtime.

Configuration files contain a mapping between option names and their values.
The format for these files looks like this:

    [option name][tab/spaces][new value]

Configuration files can be specified by adding them
to :bro:id:`Config::config_files`.  Note that in a cluster configuration,
only the manager node attempts to read the specified configuration files.

For example, simply add something like this to local.bro:

.. code:: bro

    redef Config::config_files += { "/path/to/config.dat" };

The specified configuration file will then be monitored continuously for
changes, so that writing ``TestModule::enable_feature T`` into that file will
automatically update the option's value accordingly (in a cluster
configuration, the change will be sent from the manager to all other nodes in
the cluster).  Here is an example configuration file::

    TestModule::my_networks 10.0.12.0/24,192.168.17.0/24
    TestModule::enable_feature  T
    TestModule::hostname  host-1
    TestModule::timeout 50.5
    TestModule::my_ports 80/tcp,53/udp

Note that as seen in the above example, for options of
type :bro:type:`interval`, the numeric value in the config file
is interpreted as seconds and there cannot be any time units
(such as sec, min, etc.).

Internally, the configuration framework uses the Bro input framework
with a type of input reader specifically for reading config files. Users
familiar with the Bro input framework might be aware that the input framework
is usually very strict about the syntax of input files. This is not true
for configuration files: the files need no header lines and either
tabs or spaces are accepted as separators.

If you inspect the configuration framework scripts, you will notice that the
scripts simply catch events from the input framework and then a
function :bro:see:`Config::set_value` is called to set an option to the new
value.  If you want to change an option yourself during runtime, you can
call Config::set_value directly from a script (in a cluster configuration,
this only needs to happen on the manager, as the change will be automatically
sent to all other nodes in the cluster).

Note that some data types (such as pattern, table, and record) are not
supported by the config input reader.  In that case you would need to use
the Config::set_value function to change the value of such an option as
shown in the following example.

.. code:: bro

    module TestModule;

    export {
        option host_port: table[addr] of port = {};
    }

    event bro_init() {
        local t: table[addr] of port = { [10.0.0.2] = 123/tcp };
        Config::set_value("TestModule::host_port", t);
    }

Regardless of whether an option change is triggered by a config file or by
the Config::set_value function, the change is always logged to the
log file "config.log".


Change handlers
---------------

A change handler is a user-defined function that is called automatically
each time an option value changes.  This example shows how to register a
change handler for an option that has a data type of "addr" (for other
data types, the return type and 2nd parameter data type must be adjusted
accordingly):

.. code:: bro

    module TestModule;

    export {
        option testaddr = 127.0.0.1;
    }

    # Note: the data type of 2nd parameter and return type must match
    function change_addr(ID: string, new_value: addr): addr
        {
        print fmt("Value of %s changed from %s to %s", ID, testaddr, new_value);
        return new_value;
        }

    event bro_init()
        {
        Option::set_change_handler("TestModule::testaddr", change_addr);
        }

Immediately before the specified option value is changed, the change handler
function will be called.  The value returned by the change handler is the
value finally assigned to the option. This allows, for example, checking of
values to reject invalid input (the original value can be returned to reject
the change).

It is possible define multiple change handlers for a single option.  In
this case, the change handlers are chained together: the value returned by the
first change handler is the "new value" seen by the next change handler, and
so on.  The built-in function :bro:see:`Option::set_change_handler` takes an
optional third argument that can specify a priority for the handlers.

A change handler function can optionally have a third argument of type
string.  When a config file triggers a change, then the third argument is
the pathname of the config file.  When the Config::set_value function triggers
a change, then the third argument of the change handler is the value passed
to the optional third argument of the Config::set_value function.

Note that change handlers are also used internally by the
configuration framework. If you look at the script level source code of
the config framework, you can see that change handlers are used for
logging the option changes to config.log.
