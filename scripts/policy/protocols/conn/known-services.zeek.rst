:tocdepth: 3

policy/protocols/conn/known-services.zeek
=========================================
.. zeek:namespace:: Known

This script logs and tracks services.  In the case of this script, a service
is defined as an IP address and port which has responded to and fully 
completed a TCP handshake with another host.  If a protocol is detected
during the session, the protocol will also be logged.

:Namespace: Known
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================== ======================================================
:zeek:id:`Known::service_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The timeout interval to use for operations against
                                                                                   :zeek:see:`Known::service_store`.
:zeek:id:`Known::service_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`          The hosts whose services should be tracked and logged.
================================================================================== ======================================================

Redefinable Options
###################
================================================================================= =======================================================================
:zeek:id:`Known::service_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef` The expiry interval of new entries in :zeek:see:`Known::service_store`.
:zeek:id:`Known::service_store_name`: :zeek:type:`string` :zeek:attr:`&redef`     The Broker topic name to use for :zeek:see:`Known::service_store`.
:zeek:id:`Known::use_service_store`: :zeek:type:`bool` :zeek:attr:`&redef`        Toggles between different implementations of this script.
================================================================================= =======================================================================

State Variables
###############
====================================================================================== ====================================================================
:zeek:id:`Known::service_store`: :zeek:type:`Cluster::StoreInfo`                       Holds the set of all known services.
:zeek:id:`Known::services`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` Tracks the set of daily-detected services for preventing the logging
                                                                                       of duplicates, but can also be inspected by other scripts for
                                                                                       different purposes.
====================================================================================== ====================================================================

Types
#####
===================================================== ======================================================================
:zeek:type:`Known::AddrPortPair`: :zeek:type:`record` 
:zeek:type:`Known::ServicesInfo`: :zeek:type:`record` The record type which contains the column fields of the known-services
                                                      log.
===================================================== ======================================================================

Redefinitions
#############
============================================ =============================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      The known-services logging stream identifier.
:zeek:type:`connection`: :zeek:type:`record` 
============================================ =============================================

Events
######
======================================================== ========================================================================
:zeek:id:`Known::log_known_services`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`Known::ServicesInfo`
                                                         record as it is sent on to the logging framework.
======================================================== ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Known::service_store_timeout

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::service_store`.

.. zeek:id:: Known::service_tracking

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ALL_HOSTS


   The hosts whose services should be tracked and logged.
   See :zeek:type:`Host` for possible choices.

Redefinable Options
###################
.. zeek:id:: Known::service_store_expiry

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::service_store`.
   This also changes the interval at which services get logged.

.. zeek:id:: Known::service_store_name

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/services"``

   The Broker topic name to use for :zeek:see:`Known::service_store`.

.. zeek:id:: Known::use_service_store

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. zeek:id:: Known::service_store

   :Type: :zeek:type:`Cluster::StoreInfo`
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


   Holds the set of all known services.  Keys in the store are
   :zeek:type:`Known::AddrPortPair` and their associated value is
   always the boolean value of "true".

.. zeek:id:: Known::services

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`port`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day``
   :Default: ``{}``

   Tracks the set of daily-detected services for preventing the logging
   of duplicates, but can also be inspected by other scripts for
   different purposes.
   
   In cluster operation, this set is uniformly distributed across
   proxy nodes.
   
   This set is automatically populated and shouldn't be directly modified.

Types
#####
.. zeek:type:: Known::AddrPortPair

   :Type: :zeek:type:`record`

      host: :zeek:type:`addr`

      p: :zeek:type:`port`


.. zeek:type:: Known::ServicesInfo

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

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::ServicesInfo`)

   Event that can be handled to access the :zeek:type:`Known::ServicesInfo`
   record as it is sent on to the logging framework.


