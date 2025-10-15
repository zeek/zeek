:tocdepth: 3

policy/protocols/conn/known-services.zeek
=========================================
.. zeek:namespace:: Known

This script logs and tracks active services.  For this script, an active
service is defined as an IP address and port of a server for which
a TCP handshake (SYN+ACK) is observed, assumed to have been done in the
past (started seeing packets mid-connection, but the server is actively
sending data), or sent at least one UDP packet.
If a protocol name is found/known for service, that will be logged,
but services whose names can't be determined are also still logged.

:Namespace: Known
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================================== ========================================================================
:zeek:id:`Known::service_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`     The timeout interval to use for operations against
                                                                                       :zeek:see:`Known::service_store`.
:zeek:id:`Known::service_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`              The hosts whose services should be tracked and logged.
:zeek:id:`Known::service_udp_requires_response`: :zeek:type:`bool` :zeek:attr:`&redef` Require UDP server to respond before considering it an "active service".
====================================================================================== ========================================================================

Redefinable Options
###################
================================================================================= =======================================================================
:zeek:id:`Known::service_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef` The expiry interval of new entries in :zeek:see:`Known::service_store`.
:zeek:id:`Known::service_store_name`: :zeek:type:`string` :zeek:attr:`&redef`     The Broker topic name to use for :zeek:see:`Known::service_store`.
:zeek:id:`Known::use_service_store`: :zeek:type:`bool` :zeek:attr:`&redef`        Toggles between different implementations of this script.
================================================================================= =======================================================================

State Variables
###############
======================================================================================== ====================================================================
:zeek:id:`Known::service_store`: :zeek:type:`Cluster::StoreInfo`                         Holds the set of all known services.
:zeek:id:`Known::services`: :zeek:type:`table` :zeek:attr:`&create_expire` = ``1.0 day`` Tracks the set of daily-detected services for preventing the logging
                                                                                         of duplicates, but can also be inspected by other scripts for
                                                                                         different purposes.
======================================================================================== ====================================================================

Types
#####
============================================================ ======================================================================
:zeek:type:`Known::AddrPortServTriplet`: :zeek:type:`record` 
:zeek:type:`Known::ServicesInfo`: :zeek:type:`record`        The record type which contains the column fields of the known-services
                                                             log.
============================================================ ======================================================================

Redefinitions
#############
============================================ =============================================================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      The known-services logging stream identifier.
                                             
                                             * :zeek:enum:`Known::SERVICES_LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               known_services_done: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
============================================ =============================================================================================

Events
######
======================================================== ========================================================================
:zeek:id:`Known::log_known_services`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`Known::ServicesInfo`
                                                         record as it is sent on to the logging framework.
======================================================== ========================================================================

Hooks
#####
=================================================================== =============================================
:zeek:id:`Known::log_policy_services`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
=================================================================== =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Known::service_store_timeout
   :source-code: policy/protocols/conn/known-services.zeek 69 69

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::service_store`.

.. zeek:id:: Known::service_tracking
   :source-code: policy/protocols/conn/known-services.zeek 47 47

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ALL_HOSTS


   The hosts whose services should be tracked and logged.
   See :zeek:type:`Host` for possible choices.

.. zeek:id:: Known::service_udp_requires_response
   :source-code: policy/protocols/conn/known-services.zeek 43 43

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Require UDP server to respond before considering it an "active service".

Redefinable Options
###################
.. zeek:id:: Known::service_store_expiry
   :source-code: policy/protocols/conn/known-services.zeek 65 65

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::service_store`.
   This also changes the interval at which services get logged.

.. zeek:id:: Known::service_store_name
   :source-code: policy/protocols/conn/known-services.zeek 61 61

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/services"``

   The Broker topic name to use for :zeek:see:`Known::service_store`.

.. zeek:id:: Known::use_service_store
   :source-code: policy/protocols/conn/known-services.zeek 40 40

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. zeek:id:: Known::service_store
   :source-code: policy/protocols/conn/known-services.zeek 58 58

   :Type: :zeek:type:`Cluster::StoreInfo`
   :Default:

      ::

         {
            name=<uninitialized>
            store=<uninitialized>
            master_node=""
            master=F
            backend=Broker::MEMORY
            options=[sqlite=[path="", synchronous=<uninitialized>, journal_mode=<uninitialized>, failure_mode=Broker::SQLITE_FAILURE_MODE_FAIL, integrity_check=F]]
            clone_resync_interval=10.0 secs
            clone_stale_interval=5.0 mins
            clone_mutation_buffer_interval=2.0 mins
         }


   Holds the set of all known services.  Keys in the store are
   :zeek:type:`Known::AddrPortServTriplet` and their associated value is
   always the boolean value of "true".

.. zeek:id:: Known::services
   :source-code: policy/protocols/conn/known-services.zeek 79 79

   :Type: :zeek:type:`table` [:zeek:type:`addr`, :zeek:type:`port`] of :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day``
   :Default: ``{}``

   Tracks the set of daily-detected services for preventing the logging
   of duplicates, but can also be inspected by other scripts for
   different purposes.
   
   In cluster operation, this table is uniformly distributed across
   proxy nodes.
   
   This table is automatically populated and shouldn't be directly modified.

Types
#####
.. zeek:type:: Known::AddrPortServTriplet
   :source-code: policy/protocols/conn/known-services.zeek 49 53

   :Type: :zeek:type:`record`

      host: :zeek:type:`addr`

      p: :zeek:type:`port`

      serv: :zeek:type:`string`


.. zeek:type:: Known::ServicesInfo
   :source-code: policy/protocols/conn/known-services.zeek 23 34

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time at which the service was detected.

      host: :zeek:type:`addr` :zeek:attr:`&log`
         The host address on which the service is running.

      port_num: :zeek:type:`port` :zeek:attr:`&log`
         The port number on which the service is running.

      port_proto: :zeek:type:`transport_proto` :zeek:attr:`&log`
         The transport-layer protocol which the service uses.

      service: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log`
         A set of protocols that match the service's connection payloads.

   The record type which contains the column fields of the known-services
   log.

Events
######
.. zeek:id:: Known::log_known_services
   :source-code: policy/protocols/conn/known-services.zeek 83 83

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::ServicesInfo`)

   Event that can be handled to access the :zeek:type:`Known::ServicesInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_services
   :source-code: policy/protocols/conn/known-services.zeek 19 19

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


