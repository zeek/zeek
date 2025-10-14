:tocdepth: 3

policy/frameworks/analyzer/deprecated-dpd-log.zeek
==================================================
.. zeek:namespace:: DPD

Creates the now deprecated dpd.logfile.

:Namespace: DPD

Summary
~~~~~~~
Types
#####
=========================================== ======================================================================
:zeek:type:`DPD::Info`: :zeek:type:`record` The record type defining the columns to log in the DPD logging stream.
=========================================== ======================================================================

Redefinitions
#############
============================================ ===================================================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      Add the DPD logging stream identifier.
                                             
                                             * :zeek:enum:`DPD::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               dpd: :zeek:type:`DPD::Info` :zeek:attr:`&optional`
                                             
                                               service_violation: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional`
                                                 The set of services (analyzers) for which Zeek has observed a
                                                 violation after the same service had previously been confirmed.
============================================ ===================================================================================================================

Hooks
#####
======================================================== =============================================
:zeek:id:`DPD::log_policy`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
======================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: DPD::Info
   :source-code: policy/frameworks/analyzer/deprecated-dpd-log.zeek 14 27

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when protocol analysis failed.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Connection unique ID.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      Connection ID containing the 4-tuple which identifies endpoints.


   .. zeek:field:: proto :zeek:type:`transport_proto` :zeek:attr:`&log`

      Transport protocol for the violation.


   .. zeek:field:: analyzer :zeek:type:`string` :zeek:attr:`&log`

      The analyzer that generated the violation.


   .. zeek:field:: failure_reason :zeek:type:`string` :zeek:attr:`&log`

      The textual reason for the analysis failure.


   .. zeek:field:: packet_segment :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/frameworks/dpd/packet-segment-logging.zeek` is loaded)

      A chunk of the payload that most likely resulted in the
      analyzer violation.


   The record type defining the columns to log in the DPD logging stream.

Hooks
#####
.. zeek:id:: DPD::log_policy
   :source-code: policy/frameworks/analyzer/deprecated-dpd-log.zeek 11 11

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


