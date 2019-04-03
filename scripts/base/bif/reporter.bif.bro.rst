:tocdepth: 3

base/bif/reporter.bif.bro
=========================
.. bro:namespace:: GLOBAL
.. bro:namespace:: Reporter

The reporter built-in functions allow for the scripting layer to
generate messages of varying severity.  If no event handlers
exist for reporter messages, the messages are output to stderr.
If event handlers do exist, it's assumed they take care of determining
how/where to output the messages.

See :doc:`/scripts/base/frameworks/reporter/main.bro` for a convenient
reporter message logging framework.

:Namespaces: GLOBAL, Reporter

Summary
~~~~~~~
Functions
#########
====================================================================== ========================================================================
:bro:id:`Reporter::conn_weird`: :bro:type:`function`                   Generates a "conn" weird.
:bro:id:`Reporter::error`: :bro:type:`function`                        Generates a non-fatal error indicative of a definite problem that should
                                                                       be addressed.
:bro:id:`Reporter::fatal`: :bro:type:`function`                        Generates a fatal error on stderr and terminates program execution.
:bro:id:`Reporter::fatal_error_with_core`: :bro:type:`function`        Generates a fatal error on stderr and terminates program execution
                                                                       after dumping a core file
:bro:id:`Reporter::file_weird`: :bro:type:`function`                   Generates a "file" weird.
:bro:id:`Reporter::flow_weird`: :bro:type:`function`                   Generates a "flow" weird.
:bro:id:`Reporter::get_weird_sampling_duration`: :bro:type:`function`  Gets the current weird sampling duration.
:bro:id:`Reporter::get_weird_sampling_rate`: :bro:type:`function`      Gets the current weird sampling rate.
:bro:id:`Reporter::get_weird_sampling_threshold`: :bro:type:`function` Gets the current weird sampling threshold
:bro:id:`Reporter::get_weird_sampling_whitelist`: :bro:type:`function` Gets the weird sampling whitelist
:bro:id:`Reporter::info`: :bro:type:`function`                         Generates an informational message.
:bro:id:`Reporter::net_weird`: :bro:type:`function`                    Generates a "net" weird.
:bro:id:`Reporter::set_weird_sampling_duration`: :bro:type:`function`  Sets the current weird sampling duration.
:bro:id:`Reporter::set_weird_sampling_rate`: :bro:type:`function`      Sets the weird sampling rate.
:bro:id:`Reporter::set_weird_sampling_threshold`: :bro:type:`function` Sets the current weird sampling threshold
:bro:id:`Reporter::set_weird_sampling_whitelist`: :bro:type:`function` Sets the weird sampling whitelist
:bro:id:`Reporter::warning`: :bro:type:`function`                      Generates a message that warns of a potential problem.
====================================================================== ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. bro:id:: Reporter::conn_weird

   :Type: :bro:type:`function` (name: :bro:type:`string`, c: :bro:type:`connection`, addl: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Generates a "conn" weird.
   

   :name: the name of the weird.
   

   :c: the connection associated with the weird.
   

   :addl: additional information to accompany the weird.
   

   :returns: Always true.

.. bro:id:: Reporter::error

   :Type: :bro:type:`function` (msg: :bro:type:`string`) : :bro:type:`bool`

   Generates a non-fatal error indicative of a definite problem that should
   be addressed. Program execution does not terminate.
   

   :msg: The error message to report.
   

   :returns: Always true.
   
   .. bro:see:: reporter_error

.. bro:id:: Reporter::fatal

   :Type: :bro:type:`function` (msg: :bro:type:`string`) : :bro:type:`bool`

   Generates a fatal error on stderr and terminates program execution.
   

   :msg: The error message to report.
   

   :returns: Always true.

.. bro:id:: Reporter::fatal_error_with_core

   :Type: :bro:type:`function` (msg: :bro:type:`string`) : :bro:type:`bool`

   Generates a fatal error on stderr and terminates program execution
   after dumping a core file
   

   :msg: The error message to report.
   

   :returns: Always true.

.. bro:id:: Reporter::file_weird

   :Type: :bro:type:`function` (name: :bro:type:`string`, f: :bro:type:`fa_file`, addl: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Generates a "file" weird.
   

   :name: the name of the weird.
   

   :f: the file associated with the weird.
   

   :addl: additional information to accompany the weird.
   

   :returns: true if the file was still valid, else false.

.. bro:id:: Reporter::flow_weird

   :Type: :bro:type:`function` (name: :bro:type:`string`, orig: :bro:type:`addr`, resp: :bro:type:`addr`) : :bro:type:`bool`

   Generates a "flow" weird.
   

   :name: the name of the weird.
   

   :orig: the originator host associated with the weird.
   

   :resp: the responder host associated with the weird.
   

   :returns: Always true.

.. bro:id:: Reporter::get_weird_sampling_duration

   :Type: :bro:type:`function` () : :bro:type:`interval`

   Gets the current weird sampling duration.
   

   :returns: weird sampling duration.

.. bro:id:: Reporter::get_weird_sampling_rate

   :Type: :bro:type:`function` () : :bro:type:`count`

   Gets the current weird sampling rate.
   

   :returns: weird sampling rate.

.. bro:id:: Reporter::get_weird_sampling_threshold

   :Type: :bro:type:`function` () : :bro:type:`count`

   Gets the current weird sampling threshold
   

   :returns: current weird sampling threshold.

.. bro:id:: Reporter::get_weird_sampling_whitelist

   :Type: :bro:type:`function` () : :bro:type:`string_set`

   Gets the weird sampling whitelist
   

   :returns: Current weird sampling whitelist

.. bro:id:: Reporter::info

   :Type: :bro:type:`function` (msg: :bro:type:`string`) : :bro:type:`bool`

   Generates an informational message.
   

   :msg: The informational message to report.
   

   :returns: Always true.
   
   .. bro:see:: reporter_info

.. bro:id:: Reporter::net_weird

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`bool`

   Generates a "net" weird.
   

   :name: the name of the weird.
   

   :returns: Always true.

.. bro:id:: Reporter::set_weird_sampling_duration

   :Type: :bro:type:`function` (weird_sampling_duration: :bro:type:`interval`) : :bro:type:`bool`

   Sets the current weird sampling duration. Please note that
   this will not delete already running timers.
   

   :weird_sampling_duration: New weird sampling duration.
   

   :returns: always returns True

.. bro:id:: Reporter::set_weird_sampling_rate

   :Type: :bro:type:`function` (weird_sampling_rate: :bro:type:`count`) : :bro:type:`bool`

   Sets the weird sampling rate.
   

   :weird_sampling_rate: New weird sampling rate.
   

   :returns: Always returns true.

.. bro:id:: Reporter::set_weird_sampling_threshold

   :Type: :bro:type:`function` (weird_sampling_threshold: :bro:type:`count`) : :bro:type:`bool`

   Sets the current weird sampling threshold
   

   :threshold: New weird sampling threshold.
   

   :returns: Always returns true;

.. bro:id:: Reporter::set_weird_sampling_whitelist

   :Type: :bro:type:`function` (weird_sampling_whitelist: :bro:type:`string_set`) : :bro:type:`bool`

   Sets the weird sampling whitelist
   

   :whitelist: New weird sampling rate.
   

   :returns: Always true.

.. bro:id:: Reporter::warning

   :Type: :bro:type:`function` (msg: :bro:type:`string`) : :bro:type:`bool`

   Generates a message that warns of a potential problem.
   

   :msg: The warning message to report.
   

   :returns: Always true.
   
   .. bro:see:: reporter_warning


