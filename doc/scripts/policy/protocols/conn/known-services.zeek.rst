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
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/storage/async.zeek </scripts/base/frameworks/storage/async.zeek>`, :doc:`base/frameworks/storage/sync.zeek </scripts/base/frameworks/storage/sync.zeek>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`policy/frameworks/storage/backend/sqlite </scripts/policy/frameworks/storage/backend/sqlite/index>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================================== ========================================================================
:zeek:id:`Known::service_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef`     The timeout interval to use for operations against
                                                                                       :zeek:see:`Known::service_broker_store` and
                                                                                       :zeek:see:`Known::service_store_backend`.
:zeek:id:`Known::service_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`              The hosts whose services should be tracked and logged.
:zeek:id:`Known::service_udp_requires_response`: :zeek:type:`bool` :zeek:attr:`&redef` Require UDP server to respond before considering it an "active service".
====================================================================================== ========================================================================

Redefinable Options
###################
========================================================================================================= =============================================================================
:zeek:id:`Known::service_store_backend_options`: :zeek:type:`Storage::BackendOptions` :zeek:attr:`&redef` The options for the service store.
:zeek:id:`Known::service_store_backend_type`: :zeek:type:`Storage::Backend` :zeek:attr:`&redef`           The type of storage backend to open.
:zeek:id:`Known::service_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef`                         The expiry interval of new entries in :zeek:see:`Known::service_broker_store`
                                                                                                          and :zeek:see:`Known::service_store_backend`.
:zeek:id:`Known::service_store_name`: :zeek:type:`string` :zeek:attr:`&redef`                             The Broker topic name to use for :zeek:see:`Known::service_broker_store`.
:zeek:id:`Known::service_store_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                           The name to use for :zeek:see:`Known::service_store_backend`.
:zeek:id:`Known::use_service_store`: :zeek:type:`bool` :zeek:attr:`&redef`                                Toggles between different implementations of this script.
:zeek:id:`Known::use_storage_framework`: :zeek:type:`bool` :zeek:attr:`&redef`                            Switches to the version of this script that uses the storage
                                                                                                          framework instead of Broker stores.
========================================================================================================= =============================================================================

State Variables
###############
======================================================================================== ========================================================================
:zeek:id:`Known::service_broker_store`: :zeek:type:`Cluster::StoreInfo`                  Storage configuration for Broker stores
                                                                                         Holds the set of all known services.
:zeek:id:`Known::service_store_backend`: :zeek:type:`opaque`                             Storage configuration for storage framework stores
                                                                                         This requires setting a configuration in local.zeek that sets the
                                                                                         Known::use_storage_framework boolean to T, and optionally sets different
                                                                                         values in the Known::service_store_backend_options record.
:zeek:id:`Known::services`: :zeek:type:`table` :zeek:attr:`&create_expire` = ``1.0 day`` Tracks the set of daily-detected services for preventing the logging
                                                                                         of duplicates, but can also be inspected by other scripts for
                                                                                         different purposes.
======================================================================================== ========================================================================

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
   :source-code: policy/protocols/conn/known-services.zeek 104 104

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::service_broker_store` and
   :zeek:see:`Known::service_store_backend`.

.. zeek:id:: Known::service_tracking
   :source-code: policy/protocols/conn/known-services.zeek 56 56

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ALL_HOSTS


   The hosts whose services should be tracked and logged.
   See :zeek:type:`Host` for possible choices.

.. zeek:id:: Known::service_udp_requires_response
   :source-code: policy/protocols/conn/known-services.zeek 52 52

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Require UDP server to respond before considering it an "active service".

Redefinable Options
###################
.. zeek:id:: Known::service_store_backend_options
   :source-code: policy/protocols/conn/known-services.zeek 93 93

   :Type: :zeek:type:`Storage::BackendOptions`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            serializer=Storage::STORAGE_SERIALIZER_JSON
            forced_sync=F
            redis=<uninitialized>
            sqlite=[database_path=":memory:", table_name="zeek/known/services", busy_timeout=5.0 secs, pragma_commands={
               ["integrity_check"] = "",
               ["journal_mode"] = "WAL",
               ["synchronous"] = "normal",
               ["temp_store"] = "memory"
            }, pragma_timeout=500.0 msecs, pragma_wait_on_busy=5.0 msecs]
         }


   The options for the service store. This should be redef'd in local.zeek to set
   connection information for the backend. The options default to a memory store.

.. zeek:id:: Known::service_store_backend_type
   :source-code: policy/protocols/conn/known-services.zeek 89 89

   :Type: :zeek:type:`Storage::Backend`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Storage::STORAGE_BACKEND_SQLITE``

   The type of storage backend to open.

.. zeek:id:: Known::service_store_expiry
   :source-code: policy/protocols/conn/known-services.zeek 99 99

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::service_broker_store`
   and :zeek:see:`Known::service_store_backend`.  This also changes the interval
   at which services get logged.

.. zeek:id:: Known::service_store_name
   :source-code: policy/protocols/conn/known-services.zeek 72 72

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/services"``

   The Broker topic name to use for :zeek:see:`Known::service_broker_store`.

.. zeek:id:: Known::service_store_prefix
   :source-code: policy/protocols/conn/known-services.zeek 86 86

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeekknownservices"``

   The name to use for :zeek:see:`Known::service_store_backend`. This will be used
   by the backends to differentiate tables/keys. This should be alphanumeric so
   that it can be used as the table name for the storage framework.

.. zeek:id:: Known::use_service_store
   :source-code: policy/protocols/conn/known-services.zeek 44 44

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

.. zeek:id:: Known::use_storage_framework
   :source-code: policy/protocols/conn/known-services.zeek 49 49

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Switches to the version of this script that uses the storage
   framework instead of Broker stores. This will default to ``T``
   in v8.1.

State Variables
###############
.. zeek:id:: Known::service_broker_store
   :source-code: policy/protocols/conn/known-services.zeek 69 69

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


   Storage configuration for Broker stores
   Holds the set of all known services.  Keys in the store are
   :zeek:type:`Known::AddrPortServTriplet` and their associated value is
   always the boolean value of "true".

.. zeek:id:: Known::service_store_backend
   :source-code: policy/protocols/conn/known-services.zeek 81 81

   :Type: :zeek:type:`opaque` of Storage::BackendHandle

   Storage configuration for storage framework stores
   This requires setting a configuration in local.zeek that sets the
   Known::use_storage_framework boolean to T, and optionally sets different
   values in the Known::service_store_backend_options record.
   Backend to use for storing known services data using the storage framework.

.. zeek:id:: Known::services
   :source-code: policy/protocols/conn/known-services.zeek 114 114

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
   :source-code: policy/protocols/conn/known-services.zeek 58 62

   :Type: :zeek:type:`record`


   .. zeek:field:: host :zeek:type:`addr`


   .. zeek:field:: p :zeek:type:`port`


   .. zeek:field:: serv :zeek:type:`string`



.. zeek:type:: Known::ServicesInfo
   :source-code: policy/protocols/conn/known-services.zeek 27 38

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The time at which the service was detected.


   .. zeek:field:: host :zeek:type:`addr` :zeek:attr:`&log`

      The host address on which the service is running.


   .. zeek:field:: port_num :zeek:type:`port` :zeek:attr:`&log`

      The port number on which the service is running.


   .. zeek:field:: port_proto :zeek:type:`transport_proto` :zeek:attr:`&log`

      The transport-layer protocol which the service uses.


   .. zeek:field:: service :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log`

      A set of protocols that match the service's connection payloads.


   The record type which contains the column fields of the known-services
   log.

Events
######
.. zeek:id:: Known::log_known_services
   :source-code: policy/protocols/conn/known-services.zeek 118 118

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::ServicesInfo`)

   Event that can be handled to access the :zeek:type:`Known::ServicesInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_services
   :source-code: policy/protocols/conn/known-services.zeek 23 23

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


