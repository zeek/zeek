:tocdepth: 3

base/bif/reporter.bif.zeek
==========================
.. zeek:namespace:: GLOBAL
.. zeek:namespace:: Reporter

The reporter built-in functions allow for the scripting layer to
generate messages of varying severity.  If no event handlers
exist for reporter messages, the messages are output to stderr.
If event handlers do exist, it's assumed they take care of determining
how/where to output the messages.

See :doc:`/scripts/base/frameworks/reporter/main.zeek` for a convenient
reporter message logging framework.

:Namespaces: GLOBAL, Reporter

Summary
~~~~~~~
Functions
#########
======================================================================== ========================================================================
:zeek:id:`Reporter::conn_weird`: :zeek:type:`function`                   Generates a "conn" weird.
:zeek:id:`Reporter::error`: :zeek:type:`function`                        Generates a non-fatal error indicative of a definite problem that should
                                                                         be addressed.
:zeek:id:`Reporter::fatal`: :zeek:type:`function`                        Generates a fatal error on stderr and terminates program execution.
:zeek:id:`Reporter::fatal_error_with_core`: :zeek:type:`function`        Generates a fatal error on stderr and terminates program execution
                                                                         after dumping a core file
:zeek:id:`Reporter::file_weird`: :zeek:type:`function`                   Generates a "file" weird.
:zeek:id:`Reporter::flow_weird`: :zeek:type:`function`                   Generates a "flow" weird.
:zeek:id:`Reporter::get_weird_sampling_duration`: :zeek:type:`function`  Gets the current weird sampling duration.
:zeek:id:`Reporter::get_weird_sampling_rate`: :zeek:type:`function`      Gets the current weird sampling rate.
:zeek:id:`Reporter::get_weird_sampling_threshold`: :zeek:type:`function` Gets the current weird sampling threshold
:zeek:id:`Reporter::get_weird_sampling_whitelist`: :zeek:type:`function` Gets the weird sampling whitelist
:zeek:id:`Reporter::info`: :zeek:type:`function`                         Generates an informational message.
:zeek:id:`Reporter::net_weird`: :zeek:type:`function`                    Generates a "net" weird.
:zeek:id:`Reporter::set_weird_sampling_duration`: :zeek:type:`function`  Sets the current weird sampling duration.
:zeek:id:`Reporter::set_weird_sampling_rate`: :zeek:type:`function`      Sets the weird sampling rate.
:zeek:id:`Reporter::set_weird_sampling_threshold`: :zeek:type:`function` Sets the current weird sampling threshold
:zeek:id:`Reporter::set_weird_sampling_whitelist`: :zeek:type:`function` Sets the weird sampling whitelist
:zeek:id:`Reporter::warning`: :zeek:type:`function`                      Generates a message that warns of a potential problem.
======================================================================== ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Functions
#########
.. zeek:id:: Reporter::conn_weird

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, c: :zeek:type:`connection`, addl: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Generates a "conn" weird.
   

   :name: the name of the weird.
   

   :c: the connection associated with the weird.
   

   :addl: additional information to accompany the weird.
   

   :returns: Always true.

.. zeek:id:: Reporter::error

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a non-fatal error indicative of a definite problem that should
   be addressed. Program execution does not terminate.
   

   :msg: The error message to report.
   

   :returns: Always true.
   
   .. zeek:see:: reporter_error

.. zeek:id:: Reporter::fatal

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a fatal error on stderr and terminates program execution.
   

   :msg: The error message to report.
   

   :returns: Always true.

.. zeek:id:: Reporter::fatal_error_with_core

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a fatal error on stderr and terminates program execution
   after dumping a core file
   

   :msg: The error message to report.
   

   :returns: Always true.

.. zeek:id:: Reporter::file_weird

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, f: :zeek:type:`fa_file`, addl: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Generates a "file" weird.
   

   :name: the name of the weird.
   

   :f: the file associated with the weird.
   

   :addl: additional information to accompany the weird.
   

   :returns: true if the file was still valid, else false.

.. zeek:id:: Reporter::flow_weird

   :Type: :zeek:type:`function` (name: :zeek:type:`string`, orig: :zeek:type:`addr`, resp: :zeek:type:`addr`) : :zeek:type:`bool`

   Generates a "flow" weird.
   

   :name: the name of the weird.
   

   :orig: the originator host associated with the weird.
   

   :resp: the responder host associated with the weird.
   

   :returns: Always true.

.. zeek:id:: Reporter::get_weird_sampling_duration

   :Type: :zeek:type:`function` () : :zeek:type:`interval`

   Gets the current weird sampling duration.
   

   :returns: weird sampling duration.

.. zeek:id:: Reporter::get_weird_sampling_rate

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Gets the current weird sampling rate.
   

   :returns: weird sampling rate.

.. zeek:id:: Reporter::get_weird_sampling_threshold

   :Type: :zeek:type:`function` () : :zeek:type:`count`

   Gets the current weird sampling threshold
   

   :returns: current weird sampling threshold.

.. zeek:id:: Reporter::get_weird_sampling_whitelist

   :Type: :zeek:type:`function` () : :zeek:type:`string_set`

   Gets the weird sampling whitelist
   

   :returns: Current weird sampling whitelist

.. zeek:id:: Reporter::info

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates an informational message.
   

   :msg: The informational message to report.
   

   :returns: Always true.
   
   .. zeek:see:: reporter_info

.. zeek:id:: Reporter::net_weird

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a "net" weird.
   

   :name: the name of the weird.
   

   :returns: Always true.

.. zeek:id:: Reporter::set_weird_sampling_duration

   :Type: :zeek:type:`function` (weird_sampling_duration: :zeek:type:`interval`) : :zeek:type:`bool`

   Sets the current weird sampling duration. Please note that
   this will not delete already running timers.
   

   :weird_sampling_duration: New weird sampling duration.
   

   :returns: always returns True

.. zeek:id:: Reporter::set_weird_sampling_rate

   :Type: :zeek:type:`function` (weird_sampling_rate: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the weird sampling rate.
   

   :weird_sampling_rate: New weird sampling rate.
   

   :returns: Always returns true.

.. zeek:id:: Reporter::set_weird_sampling_threshold

   :Type: :zeek:type:`function` (weird_sampling_threshold: :zeek:type:`count`) : :zeek:type:`bool`

   Sets the current weird sampling threshold
   

   :threshold: New weird sampling threshold.
   

   :returns: Always returns true;

.. zeek:id:: Reporter::set_weird_sampling_whitelist

   :Type: :zeek:type:`function` (weird_sampling_whitelist: :zeek:type:`string_set`) : :zeek:type:`bool`

   Sets the weird sampling whitelist
   

   :whitelist: New weird sampling rate.
   

   :returns: Always true.

.. zeek:id:: Reporter::warning

   :Type: :zeek:type:`function` (msg: :zeek:type:`string`) : :zeek:type:`bool`

   Generates a message that warns of a potential problem.
   

   :msg: The warning message to report.
   

   :returns: Always true.
   
   .. zeek:see:: reporter_warning


