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

Analyzer tags are also inserted into a global :zeek:type:`AllAnalyzers::Tag` enum
type. This type contains duplicates of all of the :zeek:type:`Analyzer::Tag`,
:zeek:type:`PacketAnalyzer::Tag` and :zeek:type:`Files::Tag` enum values
and can be used for arguments to function/hook/event definitions where they
need to handle any analyzer type. See :zeek:id:`Analyzer::register_for_ports`
for an example.

:Namespace: Analyzer
:Imports: :doc:`base/bif/analyzer.bif.zeek </scripts/base/bif/analyzer.bif.zeek>`, :doc:`base/bif/file_analysis.bif.zeek </scripts/base/bif/file_analysis.bif.zeek>`, :doc:`base/bif/packet_analysis.bif.zeek </scripts/base/bif/packet_analysis.bif.zeek>`, :doc:`base/frameworks/packet-filter/utils.zeek </scripts/base/frameworks/packet-filter/utils.zeek>`

Summary
~~~~~~~
State Variables
###############
============================================================================== ===================================================================
:zeek:id:`Analyzer::disable_all`: :zeek:type:`bool` :zeek:attr:`&redef`        If true, all available analyzers are initially disabled at startup.
:zeek:id:`Analyzer::disabled_analyzers`: :zeek:type:`set` :zeek:attr:`&redef`  A set of analyzers to disable by default at startup.
:zeek:id:`Analyzer::ports`: :zeek:type:`table`                                 A table of ports mapped to analyzers that handle those ports.
:zeek:id:`Analyzer::requested_analyzers`: :zeek:type:`set` :zeek:attr:`&redef` A set of protocol, packet or file analyzer tags requested to
                                                                               be enabled during startup.
============================================================================== ===================================================================

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
:zeek:id:`Analyzer::has_tag`: :zeek:type:`function`              Check whether the given analyzer name exists.
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
   :source-code: base/frameworks/analyzer/main.zeek 28 28

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, all available analyzers are initially disabled at startup.
   One can then selectively enable them with
   :zeek:id:`Analyzer::enable_analyzer`.

.. zeek:id:: Analyzer::disabled_analyzers
   :source-code: base/frameworks/analyzer/main.zeek 143 143

   :Type: :zeek:type:`set` [:zeek:type:`AllAnalyzers::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            AllAnalyzers::ANALYZER_ANALYZER_TCPSTATS
         }


   A set of analyzers to disable by default at startup. The default set
   contains legacy analyzers that are no longer supported.

.. zeek:id:: Analyzer::ports
   :source-code: base/frameworks/analyzer/main.zeek 151 151

   :Type: :zeek:type:`table` [:zeek:type:`AllAnalyzers::Tag`] of :zeek:type:`set` [:zeek:type:`port`]
   :Default: ``{}``

   A table of ports mapped to analyzers that handle those ports. This is
   used by BPF filtering and DPD. Session analyzers can add to this using
   Analyzer::register_for_port(s) and packet analyzers can add to this
   using PacketAnalyzer::register_for_port(s).

.. zeek:id:: Analyzer::requested_analyzers
   :source-code: base/frameworks/analyzer/main.zeek 161 161

   :Type: :zeek:type:`set` [:zeek:type:`AllAnalyzers::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   A set of protocol, packet or file analyzer tags requested to
   be enabled during startup.
   
   By default, all analyzers in Zeek are enabled. When all analyzers
   are disabled through :zeek:see:`Analyzer::disable_all`, this set
   set allows to record analyzers to be enabled during Zeek startup.
   
   This set can be added to via :zeek:see:`redef`.

Functions
#########
.. zeek:id:: Analyzer::all_registered_ports
   :source-code: base/frameworks/analyzer/main.zeek 235 238

   :Type: :zeek:type:`function` () : :zeek:type:`table` [:zeek:type:`AllAnalyzers::Tag`] of :zeek:type:`set` [:zeek:type:`port`]

   Returns a table of all ports-to-analyzer mappings currently registered.
   

   :returns: A table mapping each analyzer to the set of ports
            registered for it.

.. zeek:id:: Analyzer::analyzer_to_bpf
   :source-code: base/frameworks/analyzer/main.zeek 261 271

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`) : :zeek:type:`string`

   Automatically creates a BPF filter for the specified protocol based
   on the data supplied for the protocol through the
   :zeek:see:`Analyzer::register_for_ports` function.
   

   :param tag: The analyzer tag.
   

   :returns: BPF filter string.

.. zeek:id:: Analyzer::disable_analyzer
   :source-code: base/frameworks/analyzer/main.zeek 194 203

   :Type: :zeek:type:`function` (tag: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`bool`

   Disables an analyzer. Once disabled, the analyzer will not be used
   further for analysis of future connections.
   

   :param tag: The tag of the analyzer to disable.
   

   :returns: True if the analyzer was successfully disabled.

.. zeek:id:: Analyzer::enable_analyzer
   :source-code: base/frameworks/analyzer/main.zeek 183 192

   :Type: :zeek:type:`function` (tag: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`bool`

   Enables an analyzer. Once enabled, the analyzer may be used for analysis
   of future connections as decided by Zeek's dynamic protocol detection.
   

   :param tag: The tag of the analyzer to enable.
   

   :returns: True if the analyzer was successfully enabled.

.. zeek:id:: Analyzer::get_bpf
   :source-code: base/frameworks/analyzer/main.zeek 273 281

   :Type: :zeek:type:`function` () : :zeek:type:`string`

   Create a BPF filter which matches all of the ports defined
   by the various protocol analysis scripts as "registered ports"
   for the protocol.

.. zeek:id:: Analyzer::get_tag
   :source-code: base/frameworks/analyzer/main.zeek 250 253

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`AllAnalyzers::Tag`

   Translates an analyzer's name to a tag enum value.
   

   :param name: The analyzer name.
   

   :returns: The analyzer tag corresponding to the name.

.. zeek:id:: Analyzer::has_tag
   :source-code: base/frameworks/analyzer/main.zeek 245 248

   :Type: :zeek:type:`function` (name: :zeek:type:`string`) : :zeek:type:`bool`

   Check whether the given analyzer name exists.
   
   This can be used before calling :zeek:see:`Analyzer::get_tag` to
   verify that the given name as string is a valid analyzer name.
   

   :param name: The analyzer name.
   

   :returns: True if the given name is a valid analyzer, else false.

.. zeek:id:: Analyzer::name
   :source-code: base/frameworks/analyzer/main.zeek 240 243

   :Type: :zeek:type:`function` (atype: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`string`

   Translates an analyzer type to a string with the analyzer's name.
   

   :param tag: The analyzer tag.
   

   :returns: The analyzer name corresponding to the tag.

.. zeek:id:: Analyzer::register_for_port
   :source-code: base/frameworks/analyzer/main.zeek 218 228

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`, p: :zeek:type:`port`) : :zeek:type:`bool`

   Registers an individual well-known port for an analyzer. If a future
   connection on this port is seen, the analyzer will be automatically
   assigned to parsing it. The function *adds* to all ports already
   registered, it doesn't replace them.
   

   :param tag: The tag of the analyzer.
   

   :param p: The well-known port to associate with the analyzer.
   

   :returns: True if the port was successfully registered.

.. zeek:id:: Analyzer::register_for_ports
   :source-code: base/frameworks/analyzer/main.zeek 205 216

   :Type: :zeek:type:`function` (tag: :zeek:type:`Analyzer::Tag`, ports: :zeek:type:`set` [:zeek:type:`port`]) : :zeek:type:`bool`

   Registers a set of well-known ports for an analyzer. If a future
   connection on one of these ports is seen, the analyzer will be
   automatically assigned to parsing it. The function *adds* to all ports
   already registered, it doesn't replace them.
   

   :param tag: The tag of the analyzer.
   

   :param ports: The set of well-known ports to associate with the analyzer.
   

   :returns: True if the ports were successfully registered.

.. zeek:id:: Analyzer::registered_ports
   :source-code: base/frameworks/analyzer/main.zeek 230 233

   :Type: :zeek:type:`function` (tag: :zeek:type:`AllAnalyzers::Tag`) : :zeek:type:`set` [:zeek:type:`port`]

   Returns a set of all well-known ports currently registered for a
   specific analyzer.
   

   :param tag: The tag of the analyzer.
   

   :returns: The set of ports.

.. zeek:id:: Analyzer::schedule_analyzer
   :source-code: base/frameworks/analyzer/main.zeek 256 259

   :Type: :zeek:type:`function` (orig: :zeek:type:`addr`, resp: :zeek:type:`addr`, resp_p: :zeek:type:`port`, analyzer: :zeek:type:`Analyzer::Tag`, tout: :zeek:type:`interval`) : :zeek:type:`bool`

   Schedules an analyzer for a future connection originating from a
   given IP address and port.
   

   :param orig: The IP address originating a connection in the future.
         0.0.0.0 can be used as a wildcard to match any originator address.
   

   :param resp: The IP address responding to a connection from *orig*.
   

   :param resp_p: The destination port at *resp*.
   

   :param analyzer: The analyzer ID.
   

   :param tout: A timeout interval after which the scheduling request will be
         discarded if the connection has not yet been seen.
   

   :returns: True if successful.


