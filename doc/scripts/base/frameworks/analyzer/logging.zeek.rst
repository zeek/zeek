:tocdepth: 3

base/frameworks/analyzer/logging.zeek
=====================================
.. zeek:namespace:: Analyzer::Logging

Logging analyzer confirmations and violations into analyzer.log

:Namespace: Analyzer::Logging
:Imports: :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`, :doc:`base/frameworks/config </scripts/base/frameworks/config/index>`, :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================================== ==================================================================
:zeek:id:`Analyzer::Logging::enable`: :zeek:type:`bool` :zeek:attr:`&redef`                 Enable logging of analyzer violations and optionally confirmations
                                                                                            when :zeek:see:`Analyzer::Logging::include_confirmations` is set.
:zeek:id:`Analyzer::Logging::failure_data_max_size`: :zeek:type:`count` :zeek:attr:`&redef` If a violation contains information about the data causing it,
                                                                                            include at most this many bytes of it in the log.
:zeek:id:`Analyzer::Logging::ignore_analyzers`: :zeek:type:`set` :zeek:attr:`&redef`        Set of analyzers for which to not log confirmations or violations.
:zeek:id:`Analyzer::Logging::include_confirmations`: :zeek:type:`bool` :zeek:attr:`&redef`  Enable analyzer_confirmation.
:zeek:id:`Analyzer::Logging::include_disabling`: :zeek:type:`bool` :zeek:attr:`&redef`      Enable tracking of analyzers getting disabled.
=========================================================================================== ==================================================================

Types
#####
========================================================= ===========================================================================
:zeek:type:`Analyzer::Logging::Info`: :zeek:type:`record` The record type defining the columns to log in the analyzer logging stream.
========================================================= ===========================================================================

Redefinitions
#############
======================================= ===========================================
:zeek:type:`Log::ID`: :zeek:type:`enum` Add the analyzer logging stream identifier.
                                        
                                        * :zeek:enum:`Analyzer::Logging::LOG`
======================================= ===========================================

Hooks
#####
====================================================================== =============================================
:zeek:id:`Analyzer::Logging::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
====================================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Analyzer::Logging::enable
   :source-code: base/frameworks/analyzer/logging.zeek 47 47

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Enable logging of analyzer violations and optionally confirmations
   when :zeek:see:`Analyzer::Logging::include_confirmations` is set.

.. zeek:id:: Analyzer::Logging::failure_data_max_size
   :source-code: base/frameworks/analyzer/logging.zeek 64 64

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``40``

   If a violation contains information about the data causing it,
   include at most this many bytes of it in the log.

.. zeek:id:: Analyzer::Logging::ignore_analyzers
   :source-code: base/frameworks/analyzer/logging.zeek 67 67

   :Type: :zeek:type:`set` [:zeek:type:`AllAnalyzers::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Set of analyzers for which to not log confirmations or violations.

.. zeek:id:: Analyzer::Logging::include_confirmations
   :source-code: base/frameworks/analyzer/logging.zeek 54 54

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Enable analyzer_confirmation. They are usually less interesting
   outside of development of analyzers or troubleshooting scenarios.
   Setting this option may also generated multiple log entries per
   connection, minimally one for each conn.log entry with a populated
   service field.

.. zeek:id:: Analyzer::Logging::include_disabling
   :source-code: base/frameworks/analyzer/logging.zeek 60 60

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Enable tracking of analyzers getting disabled. This is mostly
   interesting for troubleshooting of analyzers in DPD scenarios.
   Setting this option may also generated multiple log entries per
   connection.

Types
#####
.. zeek:type:: Analyzer::Logging::Info
   :source-code: base/frameworks/analyzer/logging.zeek 18 43

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp of confirmation or violation.

      cause: :zeek:type:`string` :zeek:attr:`&log`
         What caused this log entry to be produced. This can
         currently be "violation" or "confirmation".

      analyzer_kind: :zeek:type:`string` :zeek:attr:`&log`
         The kind of analyzer involved. Currently "packet", "file"
         or "protocol".

      analyzer_name: :zeek:type:`string` :zeek:attr:`&log`
         The name of the analyzer as produced by :zeek:see:`Analyzer::name`
         for the analyzer's tag.

      uid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Connection UID if available.

      fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         File UID if available.

      id: :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`
         Connection identifier if available

      failure_reason: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Failure or violation reason, if available.

      failure_data: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Data causing failure or violation if available. Truncated
         to :zeek:see:`Analyzer::Logging::failure_data_max_size`.

   The record type defining the columns to log in the analyzer logging stream.

Hooks
#####
.. zeek:id:: Analyzer::Logging::log_policy
   :source-code: base/frameworks/analyzer/logging.zeek 15 15

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


