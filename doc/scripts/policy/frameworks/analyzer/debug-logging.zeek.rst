:tocdepth: 3

policy/frameworks/analyzer/debug-logging.zeek
=============================================
.. zeek:namespace:: Analyzer::DebugLogging

Logging analyzer confirmations and violations into analyzer-debug.log

:Namespace: Analyzer::DebugLogging
:Imports: :doc:`base/frameworks/analyzer </scripts/base/frameworks/analyzer/index>`, :doc:`base/frameworks/config </scripts/base/frameworks/config/index>`, :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================================ ======================================================================
:zeek:id:`Analyzer::DebugLogging::enable`: :zeek:type:`bool` :zeek:attr:`&redef`                 Enable logging of analyzer violations and optionally confirmations
                                                                                                 when :zeek:see:`Analyzer::DebugLogging::include_confirmations` is set.
:zeek:id:`Analyzer::DebugLogging::failure_data_max_size`: :zeek:type:`count` :zeek:attr:`&redef` If a violation contains information about the data causing it,
                                                                                                 include at most this many bytes of it in the log.
:zeek:id:`Analyzer::DebugLogging::ignore_analyzers`: :zeek:type:`set` :zeek:attr:`&redef`        Set of analyzers for which to not log confirmations or violations.
:zeek:id:`Analyzer::DebugLogging::include_confirmations`: :zeek:type:`bool` :zeek:attr:`&redef`  Enable analyzer_confirmation.
:zeek:id:`Analyzer::DebugLogging::include_disabling`: :zeek:type:`bool` :zeek:attr:`&redef`      Enable tracking of analyzers getting disabled.
================================================================================================ ======================================================================

Types
#####
============================================================== ===========================================================================
:zeek:type:`Analyzer::DebugLogging::Info`: :zeek:type:`record` The record type defining the columns to log in the analyzer logging stream.
============================================================== ===========================================================================

Redefinitions
#############
======================================= ===========================================
:zeek:type:`Log::ID`: :zeek:type:`enum` Add the analyzer logging stream identifier.
                                        
                                        * :zeek:enum:`Analyzer::DebugLogging::LOG`
======================================= ===========================================

Hooks
#####
=========================================================================== =============================================
:zeek:id:`Analyzer::DebugLogging::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=========================================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Analyzer::DebugLogging::enable
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 46 46

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Enable logging of analyzer violations and optionally confirmations
   when :zeek:see:`Analyzer::DebugLogging::include_confirmations` is set.

.. zeek:id:: Analyzer::DebugLogging::failure_data_max_size
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 63 63

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``40``

   If a violation contains information about the data causing it,
   include at most this many bytes of it in the log.

.. zeek:id:: Analyzer::DebugLogging::ignore_analyzers
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 66 66

   :Type: :zeek:type:`set` [:zeek:type:`AllAnalyzers::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   Set of analyzers for which to not log confirmations or violations.

.. zeek:id:: Analyzer::DebugLogging::include_confirmations
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 53 53

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Enable analyzer_confirmation. They are usually less interesting
   outside of development of analyzers or troubleshooting scenarios.
   Setting this option may also generated multiple log entries per
   connection, minimally one for each conn.log entry with a populated
   service field.

.. zeek:id:: Analyzer::DebugLogging::include_disabling
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 59 59

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Enable tracking of analyzers getting disabled. This is mostly
   interesting for troubleshooting of analyzers in DPD scenarios.
   Setting this option may also generated multiple log entries per
   connection.

Types
#####
.. zeek:type:: Analyzer::DebugLogging::Info
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 17 42

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp of confirmation or violation.


   .. zeek:field:: cause :zeek:type:`string` :zeek:attr:`&log`

      What caused this log entry to be produced. This can
      currently be "violation", "confirmation", or "disabled".


   .. zeek:field:: analyzer_kind :zeek:type:`string` :zeek:attr:`&log`

      The kind of analyzer involved. Currently "packet", "file"
      or "protocol".


   .. zeek:field:: analyzer_name :zeek:type:`string` :zeek:attr:`&log`

      The name of the analyzer as produced by :zeek:see:`Analyzer::name`
      for the analyzer's tag.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Connection UID if available.


   .. zeek:field:: fuid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      File UID if available.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`

      Connection identifier if available


   .. zeek:field:: failure_reason :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Failure or violation reason, if available.


   .. zeek:field:: failure_data :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Data causing failure or violation if available. Truncated
      to :zeek:see:`Analyzer::DebugLogging::failure_data_max_size`.


   The record type defining the columns to log in the analyzer logging stream.

Hooks
#####
.. zeek:id:: Analyzer::DebugLogging::log_policy
   :source-code: policy/frameworks/analyzer/debug-logging.zeek 14 14

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


