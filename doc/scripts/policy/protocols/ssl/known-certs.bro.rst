:tocdepth: 3

policy/protocols/ssl/known-certs.bro
====================================
.. bro:namespace:: Known

Log information about certificates while attempting to avoid duplicate
logging.

:Namespace: Known
:Imports: :doc:`base/files/x509 </scripts/base/files/x509/index>`, :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ===================================================================
:bro:id:`Known::cert_store_expiry`: :bro:type:`interval` :bro:attr:`&redef`  The expiry interval of new entries in :bro:see:`Known::cert_store`.
:bro:id:`Known::cert_store_timeout`: :bro:type:`interval` :bro:attr:`&redef` The timeout interval to use for operations against
                                                                             :bro:see:`Known::cert_store`.
:bro:id:`Known::cert_tracking`: :bro:type:`Host` :bro:attr:`&redef`          The certificates whose existence should be logged and tracked.
============================================================================ ===================================================================

Redefinable Options
###################
======================================================================= ==============================================================
:bro:id:`Known::cert_store_name`: :bro:type:`string` :bro:attr:`&redef` The Broker topic name to use for :bro:see:`Known::cert_store`.
:bro:id:`Known::use_cert_store`: :bro:type:`bool` :bro:attr:`&redef`    Toggles between different implementations of this script.
======================================================================= ==============================================================

State Variables
###############
=================================================================================================== ====================================================================
:bro:id:`Known::cert_store`: :bro:type:`Cluster::StoreInfo`                                         Holds the set of all known certificates.
:bro:id:`Known::certs`: :bro:type:`set` :bro:attr:`&create_expire` = ``1.0 day`` :bro:attr:`&redef` The set of all known certificates to store for preventing duplicate 
                                                                                                    logging.
=================================================================================================== ====================================================================

Types
#####
======================================================= =
:bro:type:`Known::AddrCertHashPair`: :bro:type:`record` 
:bro:type:`Known::CertsInfo`: :bro:type:`record`        
======================================================= =

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
=================================================== =====================================================================
:bro:id:`Known::log_known_certs`: :bro:type:`event` Event that can be handled to access the loggable record as it is sent
                                                    on to the logging framework.
=================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Known::cert_store_expiry

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :bro:see:`Known::cert_store`.
   This also changes the interval at which certs get logged.

.. bro:id:: Known::cert_store_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :bro:see:`Known::cert_store`.

.. bro:id:: Known::cert_tracking

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ALL_HOSTS``

   The certificates whose existence should be logged and tracked.
   Choices are: LOCAL_HOSTS, REMOTE_HOSTS, ALL_HOSTS, NO_HOSTS.

Redefinable Options
###################
.. bro:id:: Known::cert_store_name

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/known/certs"``

   The Broker topic name to use for :bro:see:`Known::cert_store`.

.. bro:id:: Known::use_cert_store

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Bro set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. bro:id:: Known::cert_store

   :Type: :bro:type:`Cluster::StoreInfo`
   :Default:

   ::

      {
         name=<uninitialized>
         store=<uninitialized>
         master_node=""
         master=F
         backend=Broker::MEMORY
         options=[sqlite=[path=""], rocksdb=[path=""]]
         clone_resync_interval=10.0 secs
         clone_stale_interval=5.0 mins
         clone_mutation_buffer_interval=2.0 mins
      }

   Holds the set of all known certificates.  Keys in the store are of
   type :bro:type:`Known::AddrCertHashPair` and their associated value is
   always the boolean value of "true".

.. bro:id:: Known::certs

   :Type: :bro:type:`set` [:bro:type:`addr`, :bro:type:`string`]
   :Attributes: :bro:attr:`&create_expire` = ``1.0 day`` :bro:attr:`&redef`
   :Default: ``{}``

   The set of all known certificates to store for preventing duplicate 
   logging. It can also be used from other scripts to 
   inspect if a certificate has been seen in use. The string value 
   in the set is for storing the DER formatted certificate' SHA1 hash.
   
   In cluster operation, this set is uniformly distributed across
   proxy nodes.

Types
#####
.. bro:type:: Known::AddrCertHashPair

   :Type: :bro:type:`record`

      host: :bro:type:`addr`

      hash: :bro:type:`string`


.. bro:type:: Known::CertsInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The timestamp when the certificate was detected.

      host: :bro:type:`addr` :bro:attr:`&log`
         The address that offered the certificate.

      port_num: :bro:type:`port` :bro:attr:`&log` :bro:attr:`&optional`
         If the certificate was handed out by a server, this is the 
         port that the server was listening on.

      subject: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Certificate subject.

      issuer_subject: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Certificate issuer subject.

      serial: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Serial number for the certificate.


Events
######
.. bro:id:: Known::log_known_certs

   :Type: :bro:type:`event` (rec: :bro:type:`Known::CertsInfo`)

   Event that can be handled to access the loggable record as it is sent
   on to the logging framework.


