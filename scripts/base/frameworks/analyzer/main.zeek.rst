:tocdepth: 3

base/frameworks/analyzer/main.zeek
==================================
.. zeek:namespace:: Analyzer

Framework for managing Zeek's protocol analyzers.

The analyzer framework allows to dynamically enable or disable analyzers, as
well as to manage the well-known ports which automatically activate a
particular analyzer for new connections.

Protocol analyzers are identified by unique tags of type
:zeek:type:`Analyzer::Tag`, such as :zeek:enum:`Analyzer::ANALYZER_HTTP`.
These tags are defined internally by
the analyzers themselves, and documented in their analyzer-specific
description along with the events that they generate.

:Namespace: Analyzer
:Imports: :doc:`base/bif/analyzer.bif.zeek </scripts/base/bif/analyzer.bif.zeek>`, :doc:`base/frameworks/packet-filter/utils.zeek </scripts/base/frameworks/packet-filter/utils.zeek>`

Summary
~~~~~~~
State Variables
###############
============================================================================= ===================================================================
:zeek:id:`Analyzer::disable_all`: :zeek:type:`bool` :zeek:attr:`&redef`       If true, all available analyzers are initially disabled at startup.
:zeek:id:`Analyzer::disabled_analyzers`: :zeek:type:`set` :zeek:attr:`&redef` A set of analyzers to disable by default at startup.
============================================================================= ===================================================================

Functions
#########
================================================================ =======================================================================
:zeek:id:`Analyzer::all_registered_ports`: :zeek:type:`function` Returns a table of all ports-to-analyzer mappings currently registered.
:zeek:id:`Analyzer::analyzer_to_bpf`: :zeek:type:`function`      Automatically creates a BPF filter for the specified protocol based
                                                                 on the data supplied for the protocol through the
                                                                 :zeek:see:`Analyzer::register_for_ports` function.
:zeek:id:`Analyzer::disable_analyzer`: :zeek:type:`function`     Disables an analyzer.
:zeek:id:`Analyzer::enable_analyzer`: :zeek:type:`function`      Enables an analyzer.
:zeek:id:`Analyzer::get_bpf`: :zeek:type:`function`              Create a BPF filter which matches all of the ports defined
                                                                 by the various protocol analysis scripts as "registered ports"
                                                                 for the protocol.
:zeek:id:`Analyzer::get_tag`: :zeek:type:`function`              Translates an analyzer's name to a tag enum value.
:zeek:id:`Analyzer::name`: :zeek:type:`function`                 Translates an analyzer type to a string with the analyzer's name.
:zeek:id:`Analyzer::register_for_port`: :zeek:type:`function`    Registers an individual well-known port for an analyzer.
:zeek:id:`Analyzer::register_for_ports`: :zeek:type:`function`   Registers a set of well-known ports for an analyzer.
:zeek:id:`Analyzer::registered_ports`: :zeek:type:`function`     Returns a set of all well-known ports currently registered for a
                                                                 specific analyzer.
:zeek:id:`Analyzer::schedule_analyzer`: :zeek:type:`function`    Schedules an analyzer for a future connection originating from a
                                                                 given IP address and port.
================================================================ =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. zeek:id:: Analyzer::disable_all

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, all available analyzers are initially disabled at startup.
   One can then selectively enable them with
   :zeek:id:`Analyzer::enable_analyzer`.

.. zeek:id:: Analyzer::disabled_analyzers

   :Type: :zeek:type:`set` [:zeek:type:`Analyzer::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            Analyzer::ANALYZER_STEPPINGSTONE,
            Analyzer::ANALYZER_TCPSTATS
         }


   A set of analyzers to disable by default at startup. The default set
   contains legacy analyzers that are no longer supported.

Functions
#########
.. zeek:id:: Analyzer::all_registered_ports

   :Type: :zeek:type:`function` () : :zeek:type:`table` [:zeek:type:`Analyzer::Tag`] of :zeek:type:`set` [:zeek:type:`port`]

   Returns a table of all ports-to-analyzer mappings currently registered.
   

   :returns: A table mapping each analyzer to the set of ports
            registered for it.

.. zeek:id:: Analyzer::analyzer_to_bpf

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`string`

   Automatically creates a BPF filter for the specified protocol based
   on the data supplied for the protocol through the
   :zeek:see:`Analyzer::register_for_ports` function.
   

   :tag: The analyzer tag.
   

   :returns: BPF filter string.

.. zeek:id:: Analyzer::disable_analyzer

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`bool`

   Disables an analyzer. Once disabled, the analyzer will not be used
   further for analysis of future connections.
   

   :tag: The tag of the analyzer to disable.
   

   :returns: True if the analyzer was successfully disabled.

.. zeek:id:: Analyzer::enable_analyzer

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`bool`

   Enables an analyzer. Once enabled, the analyzer may be used for analysis
   of future connections as decided by Zeek's dynamic protocol detection.
   

   :tag: The tag of the analyzer to enable.
   

   :returns: True if the analyzer was successfully enabled.

.. zeek:id:: Analyzer::get_bpf

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Create a BPF filter which matches all of the ports defined
   by the various protocol analysis scripts as "registered ports"
   for the protocol.

.. zeek:id:: Analyzer::get_tag

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`Analyzer::Tag`

   Translates an analyzer's name to a tag enum value.
   

   :name: The analyzer name.
   

   :returns: The analyzer tag corresponding to the name.

.. zeek:id:: Analyzer::name

   :Type: :zeek:type:`function` (atype: :zeek:type:`Analyzer::Tag`) : :zeek:type:`string`

   Translates an analyzer type to a string with the analyzer's name.
   

   :tag: The analyzer tag.
   

   :returns: The analyzer name corresponding to the tag.

.. zeek:id:: Analyzer::register_for_port

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`, p: :zeek:type:`port`) : :zeek:type:`bool`

   Registers an individual well-known port for an analyzer. If a future
   connection on this port is seen, the analyzer will be automatically
   assigned to parsing it. The function *adds* to all ports already
   registered, it doesn't replace them.
   

   :tag: The tag of the analyzer.
   

   :p: The well-known port to associate with the analyzer.
   

   :returns: True if the port was successfully registered.

.. zeek:id:: Analyzer::register_for_ports

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`, ports: :zeek:type:`set` [:zeek:type:`port`]) : :zeek:type:`bool`

   Registers a set of well-known ports for an analyzer. If a future
   connection on one of these ports is seen, the analyzer will be
   automatically assigned to parsing it. The function *adds* to all ports
   already registered, it doesn't replace them.
   

   :tag: The tag of the analyzer.
   

   :ports: The set of well-known ports to associate with the analyzer.
   

   :returns: True if the ports were successfully registered.

.. zeek:id:: Analyzer::registered_ports

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`set` [:zeek:type:`port`]

   Returns a set of all well-known ports currently registered for a
   specific analyzer.
   

   :tag: The tag of the analyzer.
   

   :returns: The set of ports.

.. zeek:id:: Analyzer::schedule_analyzer

   :Type: :zeek:type:`function` (orig: :zeek:type:`addr`, resp: :zeek:type:`addr`, resp_p: :zeek:type:`port`, analyzer: :zeek:type:`Analyzer::Tag`, tout: :zeek:type:`interval`) : :zeek:type:`bool`

   Schedules an analyzer for a future connection originating from a
   given IP address and port.
   

   :orig: The IP address originating a connection in the future.
         0.0.0.0 can be used as a wildcard to match any originator address.
   

   :resp: The IP address responding to a connection from *orig*.
   

   :resp_p: The destination port at *resp*.
   

   :analyzer: The analyzer ID.
   

   :tout: A timeout interval after which the scheduling request will be
         discarded if the connection has not yet been seen.
   

   :returns: True if successful.


