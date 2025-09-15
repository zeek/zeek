:tocdepth: 3

base/frameworks/analyzer/logging.zeek
=====================================
.. zeek:namespace:: Analyzer::Logging

Logging analyzer  violations into analyzer.log

:Namespace: Analyzer::Logging
:Imports: :doc:`base/frameworks/analyzer/main.zeek </scripts/base/frameworks/analyzer/main.zeek>`, :doc:`base/frameworks/logging </scripts/base/frameworks/logging/index>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================================== ==============================================================
:zeek:id:`Analyzer::Logging::failure_data_max_size`: :zeek:type:`count` :zeek:attr:`&redef` If a violation contains information about the data causing it,
                                                                                            include at most this many bytes of it in the log.
=========================================================================================== ==============================================================

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

Events
######
============================================================== ===============================================================================
:zeek:id:`Analyzer::Logging::log_analyzer`: :zeek:type:`event` An event that can be handled to access the :zeek:type:`Analyzer::Logging::Info`
                                                               record as it is sent on to the logging framework.
============================================================== ===============================================================================

Hooks
#####
====================================================================== =============================================
:zeek:id:`Analyzer::Logging::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
====================================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Analyzer::Logging::failure_data_max_size
   :source-code: base/frameworks/analyzer/logging.zeek 39 39

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``40``

   If a violation contains information about the data causing it,
   include at most this many bytes of it in the log.

Types
#####
.. zeek:type:: Analyzer::Logging::Info
   :source-code: base/frameworks/analyzer/logging.zeek 13 35

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp of the violation.


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

      Connection identifier if available.


   .. zeek:field:: proto :zeek:type:`transport_proto` :zeek:attr:`&log` :zeek:attr:`&optional`

      Transport protocol for the violation, if available.


   .. zeek:field:: failure_reason :zeek:type:`string` :zeek:attr:`&log`

      Failure or violation reason, if available.


   .. zeek:field:: failure_data :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Data causing failure or violation if available. Truncated
      to :zeek:see:`Analyzer::Logging::failure_data_max_size`.


   .. zeek:field:: packet_segment :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/frameworks/analyzer/packet-segment-logging.zeek` is loaded)

      A chunk of the payload that most likely resulted in the
      analyzer violation.


   The record type defining the columns to log in the analyzer logging stream.

Events
######
.. zeek:id:: Analyzer::Logging::log_analyzer
   :source-code: base/frameworks/analyzer/logging.zeek 43 43

   :Type: :zeek:type:`event` (rec: :zeek:type:`Analyzer::Logging::Info`)

   An event that can be handled to access the :zeek:type:`Analyzer::Logging::Info`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Analyzer::Logging::log_policy
   :source-code: policy/frameworks/analyzer/packet-segment-logging.zeek 38 50

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


