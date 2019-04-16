:tocdepth: 3

base/frameworks/dpd/main.zeek
=============================
.. bro:namespace:: DPD

Activates port-independent protocol detection and selectively disables
analyzers if protocol violations occur.

:Namespace: DPD

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ===============================================================
:bro:id:`DPD::ignore_violations`: :bro:type:`set` :bro:attr:`&redef`         Analyzers which you don't want to throw 
:bro:id:`DPD::ignore_violations_after`: :bro:type:`count` :bro:attr:`&redef` Ignore violations which go this many bytes into the connection.
============================================================================ ===============================================================

Types
#####
========================================= ======================================================================
:bro:type:`DPD::Info`: :bro:type:`record` The record type defining the columns to log in the DPD logging stream.
========================================= ======================================================================

Redefinitions
#############
========================================== ======================================
:bro:type:`Log::ID`: :bro:type:`enum`      Add the DPD logging stream identifier.
:bro:type:`connection`: :bro:type:`record` 
========================================== ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: DPD::ignore_violations

   :Type: :bro:type:`set` [:bro:type:`Analyzer::Tag`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         Analyzer::ANALYZER_DCE_RPC,
         Analyzer::ANALYZER_NTLM
      }

   Analyzers which you don't want to throw 

.. bro:id:: DPD::ignore_violations_after

   :Type: :bro:type:`count`
   :Attributes: :bro:attr:`&redef`
   :Default: ``10240``

   Ignore violations which go this many bytes into the connection.
   Set to 0 to never ignore protocol violations.

Types
#####
.. bro:type:: DPD::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when protocol analysis failed.

      uid: :bro:type:`string` :bro:attr:`&log`
         Connection unique ID.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         Connection ID containing the 4-tuple which identifies endpoints.

      proto: :bro:type:`transport_proto` :bro:attr:`&log`
         Transport protocol for the violation.

      analyzer: :bro:type:`string` :bro:attr:`&log`
         The analyzer that generated the violation.

      failure_reason: :bro:type:`string` :bro:attr:`&log`
         The textual reason for the analysis failure.

      disabled_aids: :bro:type:`set` [:bro:type:`count`]
         Disabled analyzer IDs.  This is only for internal tracking
         so as to not attempt to disable analyzers multiple times.

      packet_segment: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         (present if :doc:`/scripts/policy/frameworks/dpd/packet-segment-logging.zeek` is loaded)

         A chunk of the payload that most likely resulted in the
         protocol violation.

   The record type defining the columns to log in the DPD logging stream.


