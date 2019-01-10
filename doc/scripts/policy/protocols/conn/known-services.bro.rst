:tocdepth: 3

policy/protocols/conn/known-services.bro
========================================
.. bro:namespace:: Known

This script logs and tracks services.  In the case of this script, a service
is defined as an IP address and port which has responded to and fully 
completed a TCP handshake with another host.  If a protocol is detected
during the session, the protocol will also be logged.

:Namespace: Known
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ======================================================
:bro:id:`Known::service_store_timeout`: :bro:type:`interval` :bro:attr:`&redef` The timeout interval to use for operations against
                                                                                :bro:see:`Known::service_store`.
:bro:id:`Known::service_tracking`: :bro:type:`Host` :bro:attr:`&redef`          The hosts whose services should be tracked and logged.
=============================================================================== ======================================================

Redefinable Options
###################
============================================================================== ======================================================================
:bro:id:`Known::service_store_expiry`: :bro:type:`interval` :bro:attr:`&redef` The expiry interval of new entries in :bro:see:`Known::service_store`.
:bro:id:`Known::service_store_name`: :bro:type:`string` :bro:attr:`&redef`     The Broker topic name to use for :bro:see:`Known::service_store`.
:bro:id:`Known::use_service_store`: :bro:type:`bool` :bro:attr:`&redef`        Toggles between different implementations of this script.
============================================================================== ======================================================================

State Variables
###############
=================================================================================== ====================================================================
:bro:id:`Known::service_store`: :bro:type:`Cluster::StoreInfo`                      Holds the set of all known services.
:bro:id:`Known::services`: :bro:type:`set` :bro:attr:`&create_expire` = ``1.0 day`` Tracks the set of daily-detected services for preventing the logging
                                                                                    of duplicates, but can also be inspected by other scripts for
                                                                                    different purposes.
=================================================================================== ====================================================================

Types
#####
=================================================== ======================================================================
:bro:type:`Known::AddrPortPair`: :bro:type:`record` 
:bro:type:`Known::ServicesInfo`: :bro:type:`record` The record type which contains the column fields of the known-services
                                                    log.
=================================================== ======================================================================

Redefinitions
#############
========================================== =============================================
:bro:type:`Log::ID`: :bro:type:`enum`      The known-services logging stream identifier.
:bro:type:`connection`: :bro:type:`record` 
========================================== =============================================

Events
######
====================================================== =======================================================================
:bro:id:`Known::log_known_services`: :bro:type:`event` Event that can be handled to access the :bro:type:`Known::ServicesInfo`
                                                       record as it is sent on to the logging framework.
====================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Known::service_store_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :bro:see:`Known::service_store`.

.. bro:id:: Known::service_tracking

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ALL_HOSTS``

   The hosts whose services should be tracked and logged.
   See :bro:type:`Host` for possible choices.

Redefinable Options
###################
.. bro:id:: Known::service_store_expiry

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :bro:see:`Known::service_store`.
   This also changes the interval at which services get logged.

.. bro:id:: Known::service_store_name

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/known/services"``

   The Broker topic name to use for :bro:see:`Known::service_store`.

.. bro:id:: Known::use_service_store

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Bro set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. bro:id:: Known::service_store

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

   Holds the set of all known services.  Keys in the store are
   :bro:type:`Known::AddrPortPair` and their associated value is
   always the boolean value of "true".

.. bro:id:: Known::services

   :Type: :bro:type:`set` [:bro:type:`addr`, :bro:type:`port`]
   :Attributes: :bro:attr:`&create_expire` = ``1.0 day``
   :Default: ``{}``

   Tracks the set of daily-detected services for preventing the logging
   of duplicates, but can also be inspected by other scripts for
   different purposes.
   
   In cluster operation, this set is uniformly distributed across
   proxy nodes.
   
   This set is automatically populated and shouldn't be directly modified.

Types
#####
.. bro:type:: Known::AddrPortPair

   :Type: :bro:type:`record`

      host: :bro:type:`addr`

      p: :bro:type:`port`


.. bro:type:: Known::ServicesInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The time at which the service was detected.

      host: :bro:type:`addr` :bro:attr:`&log`
         The host address on which the service is running.

      port_num: :bro:type:`port` :bro:attr:`&log`
         The port number on which the service is running.

      port_proto: :bro:type:`transport_proto` :bro:attr:`&log`
         The transport-layer protocol which the service uses.

      service: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log`
         A set of protocols that match the service's connection payloads.

   The record type which contains the column fields of the known-services
   log.

Events
######
.. bro:id:: Known::log_known_services

   :Type: :bro:type:`event` (rec: :bro:type:`Known::ServicesInfo`)

   Event that can be handled to access the :bro:type:`Known::ServicesInfo`
   record as it is sent on to the logging framework.


