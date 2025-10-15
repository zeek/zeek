:tocdepth: 3

policy/protocols/conn/known-hosts.zeek
======================================
.. zeek:namespace:: Known

This script logs hosts that Zeek determines have performed complete TCP
handshakes and logs the address once per day (by default).  The log that
is output provides an easy way to determine a count of the IP addresses in
use on a network per day.

:Namespace: Known
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== =======================================================
:zeek:id:`Known::host_store_timeout`: :zeek:type:`interval` :zeek:attr:`&redef` The timeout interval to use for operations against
                                                                                :zeek:see:`Known::host_store`.
:zeek:id:`Known::host_tracking`: :zeek:type:`Host` :zeek:attr:`&redef`          The hosts whose existence should be logged and tracked.
=============================================================================== =======================================================

Redefinable Options
###################
============================================================================== ====================================================================
:zeek:id:`Known::host_store_expiry`: :zeek:type:`interval` :zeek:attr:`&redef` The expiry interval of new entries in :zeek:see:`Known::host_store`.
:zeek:id:`Known::host_store_name`: :zeek:type:`string` :zeek:attr:`&redef`     The Broker topic name to use for :zeek:see:`Known::host_store`.
:zeek:id:`Known::use_host_store`: :zeek:type:`bool` :zeek:attr:`&redef`        Toggles between different implementations of this script.
============================================================================== ====================================================================

State Variables
###############
======================================================================================================= ================================================================
:zeek:id:`Known::host_store`: :zeek:type:`Cluster::StoreInfo`                                           Holds the set of all known hosts.
:zeek:id:`Known::hosts`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef` The set of all known addresses to store for preventing duplicate
                                                                                                        logging of addresses.
======================================================================================================= ================================================================

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
   :source-code: policy/protocols/conn/known-hosts.zeek 50 50

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``15.0 secs``

   The timeout interval to use for operations against
   :zeek:see:`Known::host_store`.

.. zeek:id:: Known::host_tracking
   :source-code: policy/protocols/conn/known-hosts.zeek 35 35

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``LOCAL_HOSTS``
   :Redefinition: from :doc:`/scripts/policy/tuning/track-all-assets.zeek`

      ``=``::

         ALL_HOSTS


   The hosts whose existence should be logged and tracked.
   See :zeek:type:`Host` for possible choices.

Redefinable Options
###################
.. zeek:id:: Known::host_store_expiry
   :source-code: policy/protocols/conn/known-hosts.zeek 46 46

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 day``

   The expiry interval of new entries in :zeek:see:`Known::host_store`.
   This also changes the interval at which hosts get logged.

.. zeek:id:: Known::host_store_name
   :source-code: policy/protocols/conn/known-hosts.zeek 42 42

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"zeek/known/hosts"``

   The Broker topic name to use for :zeek:see:`Known::host_store`.

.. zeek:id:: Known::use_host_store
   :source-code: policy/protocols/conn/known-hosts.zeek 31 31

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   Toggles between different implementations of this script.
   When true, use a Broker data store, else use a regular Zeek set
   with keys uniformly distributed over proxy nodes in cluster
   operation.

State Variables
###############
.. zeek:id:: Known::host_store
   :source-code: policy/protocols/conn/known-hosts.zeek 39 39

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

.. zeek:id:: Known::hosts
   :source-code: policy/protocols/conn/known-hosts.zeek 60 60

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
   :source-code: policy/protocols/conn/known-hosts.zeek 19 25

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The timestamp at which the host was detected.

      host: :zeek:type:`addr` :zeek:attr:`&log`
         The address that was detected originating or responding to a
         TCP connection.

   The record type which contains the column fields of the known-hosts log.

Events
######
.. zeek:id:: Known::log_known_hosts
   :source-code: policy/protocols/conn/known-hosts.zeek 64 64

   :Type: :zeek:type:`event` (rec: :zeek:type:`Known::HostsInfo`)

   An event that can be handled to access the :zeek:type:`Known::HostsInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: Known::log_policy_hosts
   :source-code: policy/protocols/conn/known-hosts.zeek 16 16

   :Type: :zeek:type:`Log::PolicyHook`

   A default logging policy hook for the stream.


