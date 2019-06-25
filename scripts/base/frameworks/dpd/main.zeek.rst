:tocdepth: 3

base/frameworks/dpd/main.zeek
=============================
.. zeek:namespace:: DPD

Activates port-independent protocol detection and selectively disables
analyzers if protocol violations occur.

:Namespace: DPD

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ===============================================================
:zeek:id:`DPD::ignore_violations`: :zeek:type:`set` :zeek:attr:`&redef`         Analyzers which you don't want to throw 
:zeek:id:`DPD::ignore_violations_after`: :zeek:type:`count` :zeek:attr:`&redef` Ignore violations which go this many bytes into the connection.
=============================================================================== ===============================================================

Types
#####
=========================================== ======================================================================
:zeek:type:`DPD::Info`: :zeek:type:`record` The record type defining the columns to log in the DPD logging stream.
=========================================== ======================================================================

Redefinitions
#############
============================================ ======================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      Add the DPD logging stream identifier.
:zeek:type:`connection`: :zeek:type:`record` 
============================================ ======================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: DPD::ignore_violations

   :Type: :zeek:type:`set` [:zeek:type:`Analyzer::Tag`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``
   :Redefinition: from :doc:`/scripts/base/protocols/dce-rpc/main.zeek`

      ``+=``::

         Analyzer::ANALYZER_DCE_RPC

   :Redefinition: from :doc:`/scripts/base/protocols/ntlm/main.zeek`

      ``+=``::

         Analyzer::ANALYZER_NTLM


   Analyzers which you don't want to throw 

.. zeek:id:: DPD::ignore_violations_after

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``10240``

   Ignore violations which go this many bytes into the connection.
   Set to 0 to never ignore protocol violations.

Types
#####
.. zeek:type:: DPD::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when protocol analysis failed.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Connection unique ID.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         Connection ID containing the 4-tuple which identifies endpoints.

      proto: :zeek:type:`transport_proto` :zeek:attr:`&log`
         Transport protocol for the violation.

      analyzer: :zeek:type:`string` :zeek:attr:`&log`
         The analyzer that generated the violation.

      failure_reason: :zeek:type:`string` :zeek:attr:`&log`
         The textual reason for the analysis failure.

      disabled_aids: :zeek:type:`set` [:zeek:type:`count`]
         Disabled analyzer IDs.  This is only for internal tracking
         so as to not attempt to disable analyzers multiple times.

      packet_segment: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         (present if :doc:`/scripts/policy/frameworks/dpd/packet-segment-logging.zeek` is loaded)

         A chunk of the payload that most likely resulted in the
         protocol violation.

   The record type defining the columns to log in the DPD logging stream.


