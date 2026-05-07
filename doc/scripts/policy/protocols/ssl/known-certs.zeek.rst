:tocdepth: 3

policy/protocols/ssl/known-certs.zeek
=====================================
.. zeek:namespace:: Known

Log information about certificates while attempting to avoid duplicate
logging.

:Namespace: Known
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/storage/async.zeek </scripts/base/frameworks/storage/async.zeek>`, :doc:`base/frameworks/storage/sync.zeek </scripts/base/frameworks/storage/sync.zeek>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`policy/frameworks/storage/backend/sqlite </scripts/policy/frameworks/storage/backend/sqlite/index>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ===============================================================================
:zeek:id:`Known::cert_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef`  The expiry interval of new entries in :zeek:see:`Known::cert_broker_store` and
                                                                                :zeek:see:`Known::cert_store_backend`.
:zeek:id:`Known::cert_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The timeout interval to use for operations against
                                                                                :zeek:see:`Known::cert_broker_store` and :zeek:see:`Known::cert_store_backend`.
:zeek:id:`Known::cert_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`          The certificates whose existence should be logged and tracked.
=============================================================================== ===============================================================================

Redefinable Options
###################
======================================================================================================== ======================================================================
:zeek:id:`Known::cert_store_backend_options`: :zeek:type:`Storage::BackendOptions` :zeek:attr:`&redef`   The options for the cert store.
:zeek:id:`Known::cert_store_backend_type`: :zeek:type:`Storage::Backend` :zeek:attr:`&redef`             The type of storage backend to open.
:zeek:id:`Known::cert_store_name`: :zeek:type:`string` :zeek:attr:`&redef`                               The Broker topic name to use for :zeek:see:`Known::cert_broker_store`.
:zeek:id:`Known::cert_store_prefix`: :zeek:type:`string` :zeek:attr:`&redef`                             The name to use for :zeek:see:`Known::cert_store_backend`.
:zeek:id:`Known::enable_certs_persistence`: :zeek:type:`bool` :zeek:attr:`&redef`                        Use the storage framework to enable persistence of the stored
                                                                                                         certs between runs.
:zeek:id:`Known::use_cert_store`: :zeek:type:`bool` :zeek:attr:`&redef` :zeek:attr:`&deprecated` = *...* Toggles between different implementations of this script.
======================================================================================================== ======================================================================

State Variables
###############
======================================================================================================= ==============================================================================
:zeek:id:`Known::cert_broker_store`: :zeek:type:`Cluster::StoreInfo`                                    Storage configuration for Broker stores
                                                                                                        Holds the set of all known certs.
:zeek:id:`Known::cert_store_backend`: :zeek:type:`opaque`                                               Storage configuration for storage framework stores
                                                                                                        This requires setting a configuration in local.zeek that sets the
                                                                                                        Known::enable_certs_persistence boolean to T, and optionally setting different
                                                                                                        values in the Known::cert_store_backend_options record.
:zeek:id:`Known::certs`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef` The set of all known certificates to store for preventing duplicate
                                                                                                        logging.
======================================================================================================= ==============================================================================

Types
#####
========================================================= =
:zeek:type:`Known::AddrCertHashPair`: :zeek:type:`record`
:zeek:type:`Known::CertsInfo`: :zeek:type:`record`
========================================================= =

Redefinitions
#############
======================================= ===============================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                        * :zeek:enum:`Known::CERTS_LOG`
======================================= ===============================

Events
######
===================================================== =====================================================================
:zeek:id:`Known::log_known_certs`: :zeek:type:`event` Event that can be handled to access the loggable record as it is sent
                                                      on to the logging framework.
===================================================== =====================================================================

Hooks
#####
================================================================ =
:zeek:id:`Known::log_policy_certs`: :zeek:type:`Log::PolicyHook`
================================================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Known::cert_store_expiry
   :source-code: policy/protocols/ssl/known-certs.zeek 92 92

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::cert_broker_store` and
   :zeek:see:`Known::cert_store_backend`. This also changes the interval at which
   certs get logged.

.. zeek:id:: Known::cert_store_timeout
   :source-code: policy/protocols/ssl/known-certs.zeek 96 96

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::cert_broker_store` and :zeek:see:`Known::cert_store_backend`.

.. zeek:id:: Known::cert_tracking
   :source-code: policy/protocols/ssl/known-certs.zeek 38 38

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ``ALL_HOSTS``


   The certificates whose existence should be logged and tracked.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.

Redefinable Options
###################
.. zeek:id:: Known::cert_store_backend_options
   :source-code: policy/protocols/ssl/known-certs.zeek 85 85

   :Type: :zeek:type:`Storage::BackendOptions`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            serializer=Storage::STORAGE_SERIALIZER_JSON
            forced_sync=F
            redis=<uninitialized>
            sqlite=[database_path="/known/certs.sqlite", table_name="zeekknowncerts", busy_timeout=5.0 secs, pragma_commands={
               ["quick_check"] = "",
               ["journal_mode"] = "WAL",
               ["synchronous"] = "normal",
               ["temp_store"] = "memory"
            }, pragma_timeout=500.0 msecs, pragma_wait_on_busy=5.0 msecs]
         }


   The options for the cert store. This should be redef'd in local.zeek to set
   connection information for the backend. The options default to a central
   persistent sqlite database.

.. zeek:id:: Known::cert_store_backend_type
   :source-code: policy/protocols/ssl/known-certs.zeek 80 80

   :Type: :zeek:type:`Storage::Backend`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``Storage::STORAGE_BACKEND_SQLITE``

   The type of storage backend to open.

.. zeek:id:: Known::cert_store_name
   :source-code: policy/protocols/ssl/known-certs.zeek 63 63

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/certs"``

   The Broker topic name to use for :zeek:see:`Known::cert_broker_store`.

.. zeek:id:: Known::cert_store_prefix
   :source-code: policy/protocols/ssl/known-certs.zeek 77 77

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeekknowncerts"``

   The name to use for :zeek:see:`Known::cert_store_backend`. This will be used
   by the backends to differentiate tables/keys. This should be alphanumeric so
   that it can be used as the table name for the storage framework.

.. zeek:id:: Known::enable_certs_persistence
   :source-code: policy/protocols/ssl/known-certs.zeek 42 42

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Use the storage framework to enable persistence of the stored
   certs between runs.

.. zeek:id:: Known::use_cert_store
   :source-code: policy/protocols/ssl/known-certs.zeek 48 48

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef` :zeek:attr:`&deprecated` = *"Remove in v9.1. Store support has been disabled by default since Zeek 6.0 due to performance issues and will be removed."*
   :Default: ``F``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. zeek:id:: Known::cert_broker_store
   :source-code: policy/protocols/ssl/known-certs.zeek 60 60

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
   Holds the set of all known certs.  Keys in the store are
   :zeek:type:`Known::AddrPortServTriplet` and their associated value is
   always the boolean value of "true".

.. zeek:id:: Known::cert_store_backend
   :source-code: policy/protocols/ssl/known-certs.zeek 72 72

   :Type: :zeek:type:`opaque` of Storage::BackendHandle

   Storage configuration for storage framework stores
   This requires setting a configuration in local.zeek that sets the
   Known::enable_certs_persistence boolean to T, and optionally setting different
   values in the Known::cert_store_backend_options record.
   Backend to use for storing known certs data using the storage framework.

.. zeek:id:: Known::certs
   :source-code: policy/protocols/ssl/known-certs.zeek 105 105

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`
   :Default: ``{}``

   The set of all known certificates to store for preventing duplicate
   logging. It can also be used from other scripts to
   inspect if a certificate has been seen in use. The string value
   in the set is for storing the DER formatted certificate' SHA1 hash.

   In cluster operation, this set is uniformly distributed across
   proxy nodes.

Types
#####
.. zeek:type:: Known::AddrCertHashPair
   :source-code: policy/protocols/ssl/known-certs.zeek 50 53

   :Type: :zeek:type:`record`


   .. zeek:field:: host :zeek:type:`addr`


   .. zeek:field:: hash :zeek:type:`string`



.. zeek:type:: Known::CertsInfo
   :source-code: policy/protocols/ssl/known-certs.zeek 20 34

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The timestamp when the certificate was detected.


   .. zeek:field:: host :zeek:type:`addr` :zeek:attr:`&log`

      The address that offered the certificate.


   .. zeek:field:: port_num :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`

      If the certificate was handed out by a server, this is the
      port that the server was listening on.


   .. zeek:field:: subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Certificate subject.


   .. zeek:field:: issuer_subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Certificate issuer subject.


   .. zeek:field:: serial :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Serial number for the certificate.



Events
######
.. zeek:id:: Known::log_known_certs
   :source-code: policy/protocols/ssl/known-certs.zeek 109 109

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::CertsInfo`)

   Event that can be handled to access the loggable record as it is sent
   on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_certs
   :source-code: policy/protocols/ssl/known-certs.zeek 18 18

   :Type: :zeek:type:`Log::PolicyHook`



