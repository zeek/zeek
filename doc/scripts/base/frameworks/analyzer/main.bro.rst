:tocdepth: 3

base/frameworks/analyzer/main.bro
=================================
.. bro:namespace:: Analyzer

Framework for managing Bro's protocol analyzers.

The analyzer framework allows to dynamically enable or disable analyzers, as
well as to manage the well-known ports which automatically activate a
particular analyzer for new connections.

Protocol analyzers are identified by unique tags of type
:bro:type:`Analyzer::Tag`, such as :bro:enum:`Analyzer::ANALYZER_HTTP`.
These tags are defined internally by
the analyzers themselves, and documented in their analyzer-specific
description along with the events that they generate.

:Namespace: Analyzer
:Imports: :doc:`base/bif/analyzer.bif.bro </scripts/base/bif/analyzer.bif.bro>`, :doc:`base/frameworks/packet-filter/utils.bro </scripts/base/frameworks/packet-filter/utils.bro>`

Summary
~~~~~~~
State Variables
###############
========================================================================== ===================================================================
:bro:id:`Analyzer::disable_all`: :bro:type:`bool` :bro:attr:`&redef`       If true, all available analyzers are initially disabled at startup.
:bro:id:`Analyzer::disabled_analyzers`: :bro:type:`set` :bro:attr:`&redef` A set of analyzers to disable by default at startup.
========================================================================== ===================================================================

Functions
#########
============================================================== =======================================================================
:bro:id:`Analyzer::all_registered_ports`: :bro:type:`function` Returns a table of all ports-to-analyzer mappings currently registered.
:bro:id:`Analyzer::analyzer_to_bpf`: :bro:type:`function`      Automatically creates a BPF filter for the specified protocol based
                                                               on the data supplied for the protocol through the
                                                               :bro:see:`Analyzer::register_for_ports` function.
:bro:id:`Analyzer::disable_analyzer`: :bro:type:`function`     Disables an analyzer.
:bro:id:`Analyzer::enable_analyzer`: :bro:type:`function`      Enables an analyzer.
:bro:id:`Analyzer::get_bpf`: :bro:type:`function`              Create a BPF filter which matches all of the ports defined
                                                               by the various protocol analysis scripts as "registered ports"
                                                               for the protocol.
:bro:id:`Analyzer::get_tag`: :bro:type:`function`              Translates an analyzer's name to a tag enum value.
:bro:id:`Analyzer::name`: :bro:type:`function`                 Translates an analyzer type to a string with the analyzer's name.
:bro:id:`Analyzer::register_for_port`: :bro:type:`function`    Registers an individual well-known port for an analyzer.
:bro:id:`Analyzer::register_for_ports`: :bro:type:`function`   Registers a set of well-known ports for an analyzer.
:bro:id:`Analyzer::registered_ports`: :bro:type:`function`     Returns a set of all well-known ports currently registered for a
                                                               specific analyzer.
:bro:id:`Analyzer::schedule_analyzer`: :bro:type:`function`    Schedules an analyzer for a future connection originating from a
                                                               given IP address and port.
============================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
State Variables
###############
.. bro:id:: Analyzer::disable_all

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, all available analyzers are initially disabled at startup.
   One can then selectively enable them with
   :bro:id:`Analyzer::enable_analyzer`.

.. bro:id:: Analyzer::disabled_analyzers

   :Type: :bro:type:`set` [:bro:type:`Analyzer::Tag`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         Analyzer::ANALYZER_BACKDOOR,
         Analyzer::ANALYZER_INTERCONN,
         Analyzer::ANALYZER_TCPSTATS,
         Analyzer::ANALYZER_STEPPINGSTONE
      }

   A set of analyzers to disable by default at startup. The default set
   contains legacy analyzers that are no longer supported.

Functions
#########
.. bro:id:: Analyzer::all_registered_ports

   :Type: :bro:type:`function` () : :bro:type:`table` [:bro:type:`Analyzer::Tag`] of :bro:type:`set` [:bro:type:`port`]

   Returns a table of all ports-to-analyzer mappings currently registered.
   

   :returns: A table mapping each analyzer to the set of ports
            registered for it.

.. bro:id:: Analyzer::analyzer_to_bpf

   :Type: :bro:type:`function` (tag: :bro:type:`Analyzer::Tag`) : :bro:type:`string`

   Automatically creates a BPF filter for the specified protocol based
   on the data supplied for the protocol through the
   :bro:see:`Analyzer::register_for_ports` function.
   

   :tag: The analyzer tag.
   

   :returns: BPF filter string.

.. bro:id:: Analyzer::disable_analyzer

   :Type: :bro:type:`function` (tag: :bro:type:`Analyzer::Tag`) : :bro:type:`bool`

   Disables an analyzer. Once disabled, the analyzer will not be used
   further for analysis of future connections.
   

   :tag: The tag of the analyzer to disable.
   

   :returns: True if the analyzer was successfully disabled.

.. bro:id:: Analyzer::enable_analyzer

   :Type: :bro:type:`function` (tag: :bro:type:`Analyzer::Tag`) : :bro:type:`bool`

   Enables an analyzer. Once enabled, the analyzer may be used for analysis
   of future connections as decided by Bro's dynamic protocol detection.
   

   :tag: The tag of the analyzer to enable.
   

   :returns: True if the analyzer was successfully enabled.

.. bro:id:: Analyzer::get_bpf

   :Type: :bro:type:`function` () : :bro:type:`string`

   Create a BPF filter which matches all of the ports defined
   by the various protocol analysis scripts as "registered ports"
   for the protocol.

.. bro:id:: Analyzer::get_tag

   :Type: :bro:type:`function` (name: :bro:type:`string`) : :bro:type:`Analyzer::Tag`

   Translates an analyzer's name to a tag enum value.
   

   :name: The analyzer name.
   

   :returns: The analyzer tag corresponding to the name.

.. bro:id:: Analyzer::name

   :Type: :bro:type:`function` (atype: :bro:type:`Analyzer::Tag`) : :bro:type:`string`

   Translates an analyzer type to a string with the analyzer's name.
   

   :tag: The analyzer tag.
   

   :returns: The analyzer name corresponding to the tag.

.. bro:id:: Analyzer::register_for_port

   :Type: :bro:type:`function` (tag: :bro:type:`Analyzer::Tag`, p: :bro:type:`port`) : :bro:type:`bool`

   Registers an individual well-known port for an analyzer. If a future
   connection on this port is seen, the analyzer will be automatically
   assigned to parsing it. The function *adds* to all ports already
   registered, it doesn't replace them.
   

   :tag: The tag of the analyzer.
   

   :p: The well-known port to associate with the analyzer.
   

   :returns: True if the port was successfully registered.

.. bro:id:: Analyzer::register_for_ports

   :Type: :bro:type:`function` (tag: :bro:type:`Analyzer::Tag`, ports: :bro:type:`set` [:bro:type:`port`]) : :bro:type:`bool`

   Registers a set of well-known ports for an analyzer. If a future
   connection on one of these ports is seen, the analyzer will be
   automatically assigned to parsing it. The function *adds* to all ports
   already registered, it doesn't replace them.
   

   :tag: The tag of the analyzer.
   

   :ports: The set of well-known ports to associate with the analyzer.
   

   :returns: True if the ports were successfully registered.

.. bro:id:: Analyzer::registered_ports

   :Type: :bro:type:`function` (tag: :bro:type:`Analyzer::Tag`) : :bro:type:`set` [:bro:type:`port`]

   Returns a set of all well-known ports currently registered for a
   specific analyzer.
   

   :tag: The tag of the analyzer.
   

   :returns: The set of ports.

.. bro:id:: Analyzer::schedule_analyzer

   :Type: :bro:type:`function` (orig: :bro:type:`addr`, resp: :bro:type:`addr`, resp_p: :bro:type:`port`, analyzer: :bro:type:`Analyzer::Tag`, tout: :bro:type:`interval`) : :bro:type:`bool`

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


