:tocdepth: 3

policy/protocols/conn/known-hosts.bro
=====================================
.. bro:namespace:: Known

This script logs hosts that Bro determines have performed complete TCP 
handshakes and logs the address once per day (by default).  The log that 
is output provides an easy way to determine a count of the IP addresses in
use on a network per day.

:Namespace: Known
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ =======================================================
:bro:id:`Known::host_store_timeout`: :bro:type:`interval` :bro:attr:`&redef` The timeout interval to use for operations against
                                                                             :bro:see:`Known::host_store`.
:bro:id:`Known::host_tracking`: :bro:type:`Host` :bro:attr:`&redef`          The hosts whose existence should be logged and tracked.
============================================================================ =======================================================

Redefinable Options
###################
=========================================================================== ===================================================================
:bro:id:`Known::host_store_expiry`: :bro:type:`interval` :bro:attr:`&redef` The expiry interval of new entries in :bro:see:`Known::host_store`.
:bro:id:`Known::host_store_name`: :bro:type:`string` :bro:attr:`&redef`     The Broker topic name to use for :bro:see:`Known::host_store`.
:bro:id:`Known::use_host_store`: :bro:type:`bool` :bro:attr:`&redef`        Toggles between different implementations of this script.
=========================================================================== ===================================================================

State Variables
###############
=================================================================================================== =================================================================
:bro:id:`Known::host_store`: :bro:type:`Cluster::StoreInfo`                                         Holds the set of all known hosts.
:bro:id:`Known::hosts`: :bro:type:`set` :bro:attr:`&create_expire` = ``1.0 day`` :bro:attr:`&redef` The set of all known addresses to store for preventing duplicate 
                                                                                                    logging of addresses.
=================================================================================================== =================================================================

Types
#####
================================================ ========================================================================
:bro:type:`Known::HostsInfo`: :bro:type:`record` The record type which contains the column fields of the known-hosts log.
================================================ ========================================================================

Redefinitions
#############
===================================== ==========================================
:bro:type:`Log::ID`: :bro:type:`enum` The known-hosts logging stream identifier.
===================================== ==========================================

Events
######
=================================================== =======================================================================
:bro:id:`Known::log_known_hosts`: :bro:type:`event` An event that can be handled to access the :bro:type:`Known::HostsInfo`
                                                    record as it is sent on to the logging framework.
=================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: Known::host_store_timeout

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :bro:see:`Known::host_store`.

.. bro:id:: Known::host_tracking

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ALL_HOSTS``

   The hosts whose existence should be logged and tracked.
   See :bro:type:`Host` for possible choices.

Redefinable Options
###################
.. bro:id:: Known::host_store_expiry

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :bro:see:`Known::host_store`.
   This also changes the interval at which hosts get logged.

.. bro:id:: Known::host_store_name

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"bro/known/hosts"``

   The Broker topic name to use for :bro:see:`Known::host_store`.

.. bro:id:: Known::use_host_store

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Bro set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. bro:id:: Known::host_store

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

   Holds the set of all known hosts.  Keys in the store are addresses
   and their associated value will always be the "true" boolean.

.. bro:id:: Known::hosts

   :Type: :bro:type:`set` [:bro:type:`addr`]
   :Attributes: :bro:attr:`&create_expire` = ``1.0 day`` :bro:attr:`&redef`
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
.. bro:type:: Known::HostsInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The timestamp at which the host was detected.

      host: :bro:type:`addr` :bro:attr:`&log`
         The address that was detected originating or responding to a
         TCP connection.

   The record type which contains the column fields of the known-hosts log.

Events
######
.. bro:id:: Known::log_known_hosts

   :Type: :bro:type:`event` (rec: :bro:type:`Known::HostsInfo`)

   An event that can be handled to access the :bro:type:`Known::HostsInfo`
   record as it is sent on to the logging framework.


