:tocdepth: 3

policy/protocols/ssl/known-certs.zeek
=====================================
.. zeek:namespace:: Known

Log information about certificates while attempting to avoid duplicate
logging.

:Namespace: Known
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ====================================================================
:zeek:id:`Known::cert_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef`  The expiry interval of new entries in :zeek:see:`Known::cert_store`.
:zeek:id:`Known::cert_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The timeout interval to use for operations against
                                                                                :zeek:see:`Known::cert_store`.
:zeek:id:`Known::cert_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`          The certificates whose existence should be logged and tracked.
=============================================================================== ====================================================================

Redefinable Options
###################
========================================================================== ===============================================================
:zeek:id:`Known::cert_store_name`: :zeek:type:`string` :zeek:attr:`&redef` The Broker topic name to use for :zeek:see:`Known::cert_store`.
:zeek:id:`Known::use_cert_store`: :zeek:type:`bool` :zeek:attr:`&redef`    Toggles between different implementations of this script.
========================================================================== ===============================================================

State Variables
###############
======================================================================================================= ===================================================================
:zeek:id:`Known::cert_store`: :zeek:type:`Cluster::StoreInfo`                                           Holds the set of all known certificates.
:zeek:id:`Known::certs`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef` The set of all known certificates to store for preventing duplicate
                                                                                                        logging.
======================================================================================================= ===================================================================

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
   :source-code: policy/protocols/ssl/known-certs.zeek 57 57

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::cert_store`.
   This also changes the interval at which certs get logged.

.. zeek:id:: Known::cert_store_timeout
   :source-code: policy/protocols/ssl/known-certs.zeek 61 61

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::cert_store`.

.. zeek:id:: Known::cert_tracking
   :source-code: policy/protocols/ssl/known-certs.zeek 34 34

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ALL_HOSTS


   The certificates whose existence should be logged and tracked.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.

Redefinable Options
###################
.. zeek:id:: Known::cert_store_name
   :source-code: policy/protocols/ssl/known-certs.zeek 53 53

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/certs"``

   The Broker topic name to use for :zeek:see:`Known::cert_store`.

.. zeek:id:: Known::use_cert_store
   :source-code: policy/protocols/ssl/known-certs.zeek 40 40

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. zeek:id:: Known::cert_store
   :source-code: policy/protocols/ssl/known-certs.zeek 50 50

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


   Holds the set of all known certificates.  Keys in the store are of
   type :zeek:type:`Known::AddrCertHashPair` and their associated value is
   always the boolean value of "true".

.. zeek:id:: Known::certs
   :source-code: policy/protocols/ssl/known-certs.zeek 70 70

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
   :source-code: policy/protocols/ssl/known-certs.zeek 42 45

   :Type: :zeek:type:`record`

      host: :zeek:type:`addr`

      hash: :zeek:type:`string`


.. zeek:type:: Known::CertsInfo
   :source-code: policy/protocols/ssl/known-certs.zeek 16 30

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The timestamp when the certificate was detected.

      host: :zeek:type:`addr` :zeek:attr:`&log`
         The address that offered the certificate.

      port_num: :zeek:type:`port` :zeek:attr:`&log` :zeek:attr:`&optional`
         If the certificate was handed out by a server, this is the
         port that the server was listening on.

      subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Certificate subject.

      issuer_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Certificate issuer subject.

      serial: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Serial number for the certificate.


Events
######
.. zeek:id:: Known::log_known_certs
   :source-code: policy/protocols/ssl/known-certs.zeek 74 74

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::CertsInfo`)

   Event that can be handled to access the loggable record as it is sent
   on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_certs
   :source-code: policy/protocols/ssl/known-certs.zeek 14 14

   :Type: :zeek:type:`Log::PolicyHook`



