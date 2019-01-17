:tocdepth: 3

base/frameworks/netcontrol/catch-and-release.bro
================================================
.. bro:namespace:: NetControl

Implementation of catch-and-release functionality for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/netcontrol/drop.bro </scripts/base/frameworks/netcontrol/drop.bro>`, :doc:`base/frameworks/netcontrol/main.bro </scripts/base/frameworks/netcontrol/main.bro>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================================================== ====================================================================================
:bro:id:`NetControl::catch_release_warn_blocked_ip_encountered`: :bro:type:`bool` :bro:attr:`&redef` If true, catch and release warns if packets of an IP address are still seen after it
                                                                                                     should have been blocked.
==================================================================================================== ====================================================================================

Redefinable Options
###################
==================================================================================== =====================================================================================
:bro:id:`NetControl::catch_release_intervals`: :bro:type:`vector` :bro:attr:`&redef` Time intervals for which subsequent drops of the same IP take
                                                                                     effect.
:bro:id:`NetControl::watch_connections`: :bro:type:`bool` :bro:attr:`&redef`         If true, catch_release_seen is called on the connection originator in new_connection,
                                                                                     connection_established, partial_connection, connection_attempt, connection_rejected,
                                                                                     connection_reset and connection_pending
==================================================================================== =====================================================================================

Types
#####
============================================================= =========================================================================
:bro:type:`NetControl::BlockInfo`: :bro:type:`record`         This record is used for storing information about current blocks that are
                                                              part of catch and release.
:bro:type:`NetControl::CatchReleaseActions`: :bro:type:`enum` The enum that contains the different kinds of messages that are logged by
                                                              catch and release.
:bro:type:`NetControl::CatchReleaseInfo`: :bro:type:`record`  The record type that is used for representing and logging
============================================================= =========================================================================

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =

Events
######
===================================================================== ===================================================================================
:bro:id:`NetControl::catch_release_add`: :bro:type:`event`            
:bro:id:`NetControl::catch_release_block_delete`: :bro:type:`event`   
:bro:id:`NetControl::catch_release_block_new`: :bro:type:`event`      
:bro:id:`NetControl::catch_release_delete`: :bro:type:`event`         
:bro:id:`NetControl::catch_release_encountered`: :bro:type:`event`    
:bro:id:`NetControl::catch_release_forgotten`: :bro:type:`event`      Event is raised when catch and release cases management of an IP address because no
                                                                      activity was seen within the watch_until period.
:bro:id:`NetControl::log_netcontrol_catch_release`: :bro:type:`event` Event that can be handled to access the :bro:type:`NetControl::CatchReleaseInfo`
                                                                      record as it is sent on to the logging framework.
===================================================================== ===================================================================================

Functions
#########
========================================================================= ======================================================================================================
:bro:id:`NetControl::catch_release_seen`: :bro:type:`function`            This function can be called to notify the catch and release script that activity by
                                                                          an IP address was seen.
:bro:id:`NetControl::drop_address_catch_release`: :bro:type:`function`    Stops all packets involving an IP address from being forwarded.
:bro:id:`NetControl::get_catch_release_info`: :bro:type:`function`        Get the :bro:see:`NetControl::BlockInfo` record for an address currently blocked by catch and release.
:bro:id:`NetControl::unblock_address_catch_release`: :bro:type:`function` Removes an address from being watched with catch and release.
========================================================================= ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: NetControl::catch_release_warn_blocked_ip_encountered

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   If true, catch and release warns if packets of an IP address are still seen after it
   should have been blocked.

Redefinable Options
###################
.. bro:id:: NetControl::catch_release_intervals

   :Type: :bro:type:`vector` of :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      [10.0 mins, 1.0 hr, 1.0 day, 7.0 days]

   Time intervals for which subsequent drops of the same IP take
   effect.

.. bro:id:: NetControl::watch_connections

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   If true, catch_release_seen is called on the connection originator in new_connection,
   connection_established, partial_connection, connection_attempt, connection_rejected,
   connection_reset and connection_pending

Types
#####
.. bro:type:: NetControl::BlockInfo

   :Type: :bro:type:`record`

      block_until: :bro:type:`time` :bro:attr:`&optional`
         Absolute time indicating until when a block is inserted using NetControl.

      watch_until: :bro:type:`time`
         Absolute time indicating until when an IP address is watched to reblock it.

      num_reblocked: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Number of times an IP address was reblocked.

      current_interval: :bro:type:`count`
         Number indicating at which catch and release interval we currently are.

      current_block_id: :bro:type:`string`
         ID of the inserted block, if any.

      location: :bro:type:`string` :bro:attr:`&optional`
         User specified string.

   This record is used for storing information about current blocks that are
   part of catch and release.

.. bro:type:: NetControl::CatchReleaseActions

   :Type: :bro:type:`enum`

      .. bro:enum:: NetControl::INFO NetControl::CatchReleaseActions

         Log lines marked with info are purely informational; no action was taken.

      .. bro:enum:: NetControl::ADDED NetControl::CatchReleaseActions

         A rule for the specified IP address already existed in NetControl (outside
         of catch-and-release). Catch and release did not add a new rule, but is now
         watching the IP address and will add a new rule after the current rule expires.

      .. bro:enum:: NetControl::DROP NetControl::CatchReleaseActions

         (present if :doc:`/scripts/base/frameworks/netcontrol/types.bro` is loaded)


         Stop forwarding all packets matching the entity.
         
         No additional arguments.

      .. bro:enum:: NetControl::DROPPED NetControl::CatchReleaseActions

         A drop was requested by catch and release.
         An address was successfully blocked by catch and release.

      .. bro:enum:: NetControl::UNBLOCK NetControl::CatchReleaseActions

         An address was unblocked after the timeout expired.

      .. bro:enum:: NetControl::FORGOTTEN NetControl::CatchReleaseActions

         An address was forgotten because it did not reappear within the `watch_until` interval.

      .. bro:enum:: NetControl::SEEN_AGAIN NetControl::CatchReleaseActions

         A watched IP address was seen again; catch and release will re-block it.

   The enum that contains the different kinds of messages that are logged by
   catch and release.

.. bro:type:: NetControl::CatchReleaseInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         The absolute time indicating when the action for this log-line occured.

      rule_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The rule id that this log line refers to.

      ip: :bro:type:`addr` :bro:attr:`&log`
         The IP address that this line refers to.

      action: :bro:type:`NetControl::CatchReleaseActions` :bro:attr:`&log`
         The action that was taken in this log-line.

      block_interval: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         The current block_interaval (for how long the address is blocked).

      watch_interval: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         The current watch_interval (for how long the address will be watched and re-block if it reappears).

      blocked_until: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         The absolute time until which the address is blocked.

      watched_until: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         The absolute time until which the address will be monitored.

      num_blocked: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Number of times that this address was blocked in the current cycle.

      location: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The user specified location string.

      message: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Additional informational string by the catch and release framework about this log-line.

   The record type that is used for representing and logging

Events
######
.. bro:id:: NetControl::catch_release_add

   :Type: :bro:type:`event` (a: :bro:type:`addr`, location: :bro:type:`string`)


.. bro:id:: NetControl::catch_release_block_delete

   :Type: :bro:type:`event` (a: :bro:type:`addr`)


.. bro:id:: NetControl::catch_release_block_new

   :Type: :bro:type:`event` (a: :bro:type:`addr`, b: :bro:type:`NetControl::BlockInfo`)


.. bro:id:: NetControl::catch_release_delete

   :Type: :bro:type:`event` (a: :bro:type:`addr`, reason: :bro:type:`string`)


.. bro:id:: NetControl::catch_release_encountered

   :Type: :bro:type:`event` (a: :bro:type:`addr`)


.. bro:id:: NetControl::catch_release_forgotten

   :Type: :bro:type:`event` (a: :bro:type:`addr`, bi: :bro:type:`NetControl::BlockInfo`)

   Event is raised when catch and release cases management of an IP address because no
   activity was seen within the watch_until period.
   

   :a: The address that is no longer being managed.
   

   :bi: The :bro:see:`NetControl::BlockInfo` record containing information about the block.

.. bro:id:: NetControl::log_netcontrol_catch_release

   :Type: :bro:type:`event` (rec: :bro:type:`NetControl::CatchReleaseInfo`)

   Event that can be handled to access the :bro:type:`NetControl::CatchReleaseInfo`
   record as it is sent on to the logging framework.

Functions
#########
.. bro:id:: NetControl::catch_release_seen

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`void`

   This function can be called to notify the catch and release script that activity by
   an IP address was seen. If the respective IP address is currently monitored by catch and
   release and not blocked, the block will be reinstated. See the documentation of watch_new_connection
   which events the catch and release functionality usually monitors for activity.
   

   :a: The address that was seen and should be re-dropped if it is being watched.

.. bro:id:: NetControl::drop_address_catch_release

   :Type: :bro:type:`function` (a: :bro:type:`addr`, location: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`NetControl::BlockInfo`

   Stops all packets involving an IP address from being forwarded. This function
   uses catch-and-release functionality, where the IP address is only dropped for
   a short amount of time that is incremented steadily when the IP is encountered
   again.
   
   In cluster mode, this function works on workers as well as the manager. On managers,
   the returned :bro:see:`NetControl::BlockInfo` record will not contain the block ID,
   which will be assigned on the manager.
   

   :a: The address to be dropped.
   

   :t: How long to drop it, with 0 being indefinitely.
   

   :location: An optional string describing where the drop was triggered.
   

   :returns: The :bro:see:`NetControl::BlockInfo` record containing information about
            the inserted block.

.. bro:id:: NetControl::get_catch_release_info

   :Type: :bro:type:`function` (a: :bro:type:`addr`) : :bro:type:`NetControl::BlockInfo`

   Get the :bro:see:`NetControl::BlockInfo` record for an address currently blocked by catch and release.
   If the address is unknown to catch and release, the watch_until time will be set to 0.
   
   In cluster mode, this function works on the manager and workers. On workers, the data will
   lag slightly behind the manager; if you add a block, it will not be instantly available via
   this function.
   

   :a: The address to get information about.
   

   :returns: The :bro:see:`NetControl::BlockInfo` record containing information about
            the inserted block.

.. bro:id:: NetControl::unblock_address_catch_release

   :Type: :bro:type:`function` (a: :bro:type:`addr`, reason: :bro:type:`string` :bro:attr:`&default` = ``""`` :bro:attr:`&optional`) : :bro:type:`bool`

   Removes an address from being watched with catch and release. Returns true if the
   address was found and removed; returns false if it was unknown to catch and release.
   
   If the address is currently blocked, and the block was inserted by catch and release,
   the block is removed.
   

   :a: The address to be unblocked.
   

   :reason: A reason for the unblock.
   

   :returns: True if the address was unblocked.


