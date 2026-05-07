:tocdepth: 3

policy/protocols/conn/known-hosts.zeek
======================================
.. zeek:namespace:: Known

This script logs hosts that Zeek determines have performed complete TCP
handshakes and logs the address once per day (by default).  The log that
is output provides an easy way to determine a count of the IP addresses in
use on a network per day.

:Namespace: Known
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/storage/async.zeek </scripts/base/frameworks/storage/async.zeek>`, :doc:`base/frameworks/storage/sync.zeek </scripts/base/frameworks/storage/sync.zeek>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`policy/frameworks/storage/backend/sqlite </scripts/policy/frameworks/storage/backend/sqlite/index>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ===============================================================================
:zeek:id:`Known::host_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The timeout interval to use for operations against
                                                                                :zeek:see:`Known::host_broker_store` and :zeek:see:`Known::host_store_backend`.
:zeek:id:`Known::host_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`          The hosts whose existence should be logged and tracked.
=============================================================================== ===============================================================================

Redefinable Options
###################
======================================================================================================== ==============================================================================
:zeek:id:`Known::enable_hosts_persistence`: :zeek:type:`bool` :zeek:attr:`&redef`                        Use the storage framework to enable persistence of the stored
                                                                                                         hosts between runs.
:zeek:id:`Known::host_store_backend_options`: :zeek:type:`Storage::BackendOptions` :zeek:attr:`&redef`   The options for the host store.
:zeek:id:`Known::host_store_backend_type`: :zeek:type:`Storage::Backend` :zeek:attr:`&redef`             The type of storage backend to open.
:zeek:id:`Known::host_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef`                           The expiry interval of new entries in :zeek:see:`Known::host_broker_store` and
                                                                                                         :zeek:see:`Known::host_store_backend`.
:zeek:id:`Known::host_store_name`: :zeek:type:`string` :zeek:attr:`&redef`                               The Broker topic name to use for :zeek:see:`Known::host_broker_store`.
:zeek:id:`Known::host_store_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                             The name to use for :zeek:see:`Known::host_store_backend`.
:zeek:id:`Known::use_host_store`: :zeek:type:`bool` :zeek:attr:`&redef` :zeek:attr:`&deprecated` = *...* Toggles between different implementations of this script.
======================================================================================================== ==============================================================================

State Variables
###############
======================================================================================================= ==============================================================================
:zeek:id:`Known::host_broker_store`: :zeek:type:`Cluster::StoreInfo`                                    Holds the set of all known hosts.
:zeek:id:`Known::host_store_backend`: :zeek:type:`opaque`                                               This requires setting a configuration in local.zeek that sets the
                                                                                                        Known::enable_hosts_persistence boolean to T, and optionally setting different
                                                                                                        values in the Known::host_store_backend_options record.
:zeek:id:`Known::hosts`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef` The set of all known addresses to store for preventing duplicate
                                                                                                        logging of addresses.
======================================================================================================= ==============================================================================

Types
#####
================================================== ========================================================================
:zeek:type:`Known::HostsInfo`: :zeek:type:`record` The record type which contains the column fields of the known-hosts log.
================================================== ========================================================================

Redefinitions
#############
======================================= ==========================================
:zeek:type:`Log::ID`: :zeek:type:`enum` The known-hosts logging stream identifier.

                                        * :zeek:enum:`Known::HOSTS_LOG`
======================================= ==========================================

Events
######
===================================================== ========================================================================
:zeek:id:`Known::log_known_hosts`: :zeek:type:`event` An event that can be handled to access the :zeek:type:`Known::HostsInfo`
                                                      record as it is sent on to the logging framework.
===================================================== ========================================================================

Hooks
#####
================================================================ =============================================
:zeek:id:`Known::log_policy_hosts`: :zeek:type:`Log::PolicyHook` A default logging policy hook for the stream.
================================================================ =============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Known::host_store_timeout
   :source-code: policy/protocols/conn/known-hosts.zeek 81 81

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::host_broker_store` and :zeek:see:`Known::host_store_backend`.

.. zeek:id:: Known::host_tracking
   :source-code: policy/protocols/conn/known-hosts.zeek 43 43

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ``ALL_HOSTS``


   The hosts whose existence should be logged and tracked.
   See :zeek:type:`Host` for possible choices.

Redefinable Options
###################
.. zeek:id:: Known::enable_hosts_persistence
   :source-code: policy/protocols/conn/known-hosts.zeek 33 33

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Use the storage framework to enable persistence of the stored
   hosts between runs.

.. zeek:id:: Known::host_store_backend_options
   :source-code: policy/protocols/conn/known-hosts.zeek 70 70

   :Type: :zeek:type:`Storage::BackendOptions`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            serializer=Storage::STORAGE_SERIALIZER_JSON
            forced_sync=F
            redis=<uninitialized>
            sqlite=[database_path="/known/hosts.sqlite", table_name="zeekknownhosts", busy_timeout=5.0 secs, pragma_commands={
               ["quick_check"] = "",
               ["journal_mode"] = "WAL",
               ["synchronous"] = "normal",
               ["temp_store"] = "memory"
            }, pragma_timeout=500.0 msecs, pragma_wait_on_busy=5.0 msecs]
         }


   The options for the host store. This should be redef'd in local.zeek to set
   connection information for the backend. The options default to a central
   persistent sqlite database.

.. zeek:id:: Known::host_store_backend_type
   :source-code: policy/protocols/conn/known-hosts.zeek 65 65

   :Type: :zeek:type:`Storage::Backend`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Storage::STORAGE_BACKEND_SQLITE``

   The type of storage backend to open.

.. zeek:id:: Known::host_store_expiry
   :source-code: policy/protocols/conn/known-hosts.zeek 77 77

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::host_broker_store` and
   :zeek:see:`Known::host_store_backend`. This also changes the interval at
   which hosts get logged.

.. zeek:id:: Known::host_store_name
   :source-code: policy/protocols/conn/known-hosts.zeek 50 50

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/hosts"``

   The Broker topic name to use for :zeek:see:`Known::host_broker_store`.

.. zeek:id:: Known::host_store_prefix
   :source-code: policy/protocols/conn/known-hosts.zeek 62 62

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeekknownhosts"``

   The name to use for :zeek:see:`Known::host_store_backend`. This will be used
   by the backends to differentiate tables/keys. This should be alphanumeric so
   that it can be used as the table name for the storage framework.

.. zeek:id:: Known::use_host_store
   :source-code: policy/protocols/conn/known-hosts.zeek 39 39

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef` :zeek:attr:`&deprecated` = *"Remove in v9.1. Store support has been disabled by default since Zeek 6.0 due to performance and will be removed."*
   :Default: ``F``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. zeek:id:: Known::host_broker_store
   :source-code: policy/protocols/conn/known-hosts.zeek 47 47

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


   Holds the set of all known hosts.  Keys in the store are addresses
   and their associated value will always be the "true" boolean.

.. zeek:id:: Known::host_store_backend
   :source-code: policy/protocols/conn/known-hosts.zeek 57 57

   :Type: :zeek:type:`opaque` of Storage::BackendHandle

   This requires setting a configuration in local.zeek that sets the
   Known::enable_hosts_persistence boolean to T, and optionally setting different
   values in the Known::host_store_backend_options record.
   Backend to use for storing known hosts data using the storage framework.

.. zeek:id:: Known::hosts
   :source-code: policy/protocols/conn/known-hosts.zeek 91 91

   :Type: :zeek:type:`set` [:zeek:type:`addr`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`
   :Default: ``{}``

   The set of all known addresses to store for preventing duplicate
   logging of addresses.  It can also be used from other scripts to
   inspect if an address has been seen in use.
   Maintain the list of known hosts for 24 hours so that the existence
   of each individual address is logged each day.

   In cluster operation, this set is distributed uniformly across
   proxy nodes.

Types
#####
.. zeek:type:: Known::HostsInfo
   :source-code: policy/protocols/conn/known-hosts.zeek 23 29

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The timestamp at which the host was detected.


   .. zeek:field:: host :zeek:type:`addr` :zeek:attr:`&log`

      The address that was detected originating or responding to a
      TCP connection.


   The record type which contains the column fields of the known-hosts log.

Events
######
.. zeek:id:: Known::log_known_hosts
   :source-code: policy/protocols/conn/known-hosts.zeek 95 95

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::HostsInfo`)

   An event that can be handled to access the :zeek:type:`Known::HostsInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_hosts
   :source-code: policy/protocols/conn/known-hosts.zeek 20 20

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


