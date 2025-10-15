:orphan:

Package: base/frameworks/analyzer
=================================

The analyzer framework allows to dynamically enable or disable Zeek's
protocol analyzers, as well as to manage the well-known ports which
automatically activate a particular analyzer for new connections.

:doc:`/scripts/base/frameworks/analyzer/main.zeek`

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

:doc:`/scripts/base/frameworks/analyzer/__load__.zeek`


:doc:`/scripts/base/frameworks/analyzer/dpd.zeek`

   Activates port-independent protocol detection and selectively disables
   analyzers if protocol violations occur.

:doc:`/scripts/base/frameworks/analyzer/logging.zeek`

   Logging analyzer confirmations and violations into analyzer.log

