:tocdepth: 3

policy/frameworks/netcontrol/catch-and-release.zeek
===================================================
.. zeek:namespace:: NetControl

Implementation of catch-and-release functionality for NetControl.

:Namespace: NetControl
:Imports: :doc:`base/frameworks/cluster </scripts/base/frameworks/cluster/index>`, :doc:`base/frameworks/netcontrol </scripts/base/frameworks/netcontrol/index>`

Summary
~~~~~~~
Runtime Options
###############
======================================================================================================= ====================================================================================
:zeek:id:`NetControl::catch_release_warn_blocked_ip_encountered`: :zeek:type:`bool` :zeek:attr:`&redef` If true, catch and release warns if packets of an IP address are still seen after it
                                                                                                        should have been blocked.
======================================================================================================= ====================================================================================

Redefinable Options
###################
======================================================================================= =====================================================================================
:zeek:id:`NetControl::catch_release_intervals`: :zeek:type:`vector` :zeek:attr:`&redef` Time intervals for which subsequent drops of the same IP take
                                                                                        effect.
:zeek:id:`NetControl::watch_connections`: :zeek:type:`bool` :zeek:attr:`&redef`         If true, catch_release_seen is called on the connection originator in new_connection,
                                                                                        connection_established, partial_connection, connection_attempt, connection_rejected,
                                                                                        connection_reset and connection_pending
======================================================================================= =====================================================================================

Types
#####
=============================================================== =========================================================================
:zeek:type:`NetControl::BlockInfo`: :zeek:type:`record`         This record is used for storing information about current blocks that are
                                                                part of catch and release.
:zeek:type:`NetControl::CatchReleaseActions`: :zeek:type:`enum` The enum that contains the different kinds of messages that are logged by
                                                                catch and release.
:zeek:type:`NetControl::CatchReleaseInfo`: :zeek:type:`record`  The record type that is used for representing and logging
=============================================================== =========================================================================

Redefinitions
#############
======================================= ========================================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`NetControl::CATCH_RELEASE`
======================================= ========================================

Events
######
======================================================================= ===================================================================================
:zeek:id:`NetControl::catch_release_add`: :zeek:type:`event`            
:zeek:id:`NetControl::catch_release_block_delete`: :zeek:type:`event`   
:zeek:id:`NetControl::catch_release_block_new`: :zeek:type:`event`      
:zeek:id:`NetControl::catch_release_delete`: :zeek:type:`event`         
:zeek:id:`NetControl::catch_release_encountered`: :zeek:type:`event`    
:zeek:id:`NetControl::catch_release_forgotten`: :zeek:type:`event`      Event is raised when catch and release cases management of an IP address because no
                                                                        activity was seen within the watch_until period.
:zeek:id:`NetControl::log_netcontrol_catch_release`: :zeek:type:`event` Event that can be handled to access the :zeek:type:`NetControl::CatchReleaseInfo`
                                                                        record as it is sent on to the logging framework.
======================================================================= ===================================================================================

Hooks
#####
============================================================================= =
:zeek:id:`NetControl::log_policy_catch_release`: :zeek:type:`Log::PolicyHook` 
============================================================================= =

Functions
#########
=========================================================================== =======================================================================================================
:zeek:id:`NetControl::catch_release_seen`: :zeek:type:`function`            This function can be called to notify the catch and release script that activity by
                                                                            an IP address was seen.
:zeek:id:`NetControl::drop_address_catch_release`: :zeek:type:`function`    Stops all packets involving an IP address from being forwarded.
:zeek:id:`NetControl::get_catch_release_info`: :zeek:type:`function`        Get the :zeek:see:`NetControl::BlockInfo` record for an address currently blocked by catch and release.
:zeek:id:`NetControl::unblock_address_catch_release`: :zeek:type:`function` Removes an address from being watched with catch and release.
=========================================================================== =======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: NetControl::catch_release_warn_blocked_ip_encountered
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 148 148

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   If true, catch and release warns if packets of an IP address are still seen after it
   should have been blocked.

Redefinable Options
###################
.. zeek:id:: NetControl::catch_release_intervals
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 152 152

   :Type: :zeek:type:`vector` of :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         [10.0 mins, 1.0 hr, 1.0 day, 7.0 days]


   Time intervals for which subsequent drops of the same IP take
   effect.

.. zeek:id:: NetControl::watch_connections
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 144 144

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   If true, catch_release_seen is called on the connection originator in new_connection,
   connection_established, partial_connection, connection_attempt, connection_rejected,
   connection_reset and connection_pending

Types
#####
.. zeek:type:: NetControl::BlockInfo
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 16 29

   :Type: :zeek:type:`record`


   .. zeek:field:: block_until :zeek:type:`time` :zeek:attr:`&optional`

      Absolute time indicating until when a block is inserted using NetControl.


   .. zeek:field:: watch_until :zeek:type:`time`

      Absolute time indicating until when an IP address is watched to reblock it.


   .. zeek:field:: num_reblocked :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Number of times an IP address was reblocked.


   .. zeek:field:: current_interval :zeek:type:`count`

      Number indicating at which catch and release interval we currently are.


   .. zeek:field:: current_block_id :zeek:type:`string`

      ID of the inserted block, if any.


   .. zeek:field:: location :zeek:type:`string` :zeek:attr:`&optional`

      User specified string.


   This record is used for storing information about current blocks that are
   part of catch and release.

.. zeek:type:: NetControl::CatchReleaseActions
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 33 51

   :Type: :zeek:type:`enum`

      .. zeek:enum:: NetControl::INFO NetControl::CatchReleaseActions

         Log lines marked with info are purely informational; no action was taken.

      .. zeek:enum:: NetControl::ADDED NetControl::CatchReleaseActions

         A rule for the specified IP address already existed in NetControl (outside
         of catch-and-release). Catch and release did not add a new rule, but is now
         watching the IP address and will add a new rule after the current rule expires.

      .. zeek:enum:: NetControl::DROP_REQUESTED NetControl::CatchReleaseActions

         A drop was requested by catch and release.

      .. zeek:enum:: NetControl::DROPPED NetControl::CatchReleaseActions

         An address was successfully blocked by catch and release.

      .. zeek:enum:: NetControl::UNBLOCK NetControl::CatchReleaseActions

         An address was unblocked after the timeout expired.

      .. zeek:enum:: NetControl::FORGOTTEN NetControl::CatchReleaseActions

         An address was forgotten because it did not reappear within the `watch_until` interval.

      .. zeek:enum:: NetControl::SEEN_AGAIN NetControl::CatchReleaseActions

         A watched IP address was seen again; catch and release will re-block it.

   The enum that contains the different kinds of messages that are logged by
   catch and release.

.. zeek:type:: NetControl::CatchReleaseInfo
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 53 78

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      The absolute time indicating when the action for this log-line occurred.


   .. zeek:field:: rule_id :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The rule id that this log line refers to.


   .. zeek:field:: ip :zeek:type:`addr` :zeek:attr:`&log`

      The IP address that this line refers to.


   .. zeek:field:: action :zeek:type:`NetControl::CatchReleaseActions` :zeek:attr:`&log`

      The action that was taken in this log-line.


   .. zeek:field:: block_interval :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      The current block_interval (for how long the address is blocked).


   .. zeek:field:: watch_interval :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`

      The current watch_interval (for how long the address will be watched and re-block if it reappears).


   .. zeek:field:: blocked_until :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      The absolute time until which the address is blocked.


   .. zeek:field:: watched_until :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      The absolute time until which the address will be monitored.


   .. zeek:field:: num_blocked :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Number of times that this address was blocked in the current cycle.


   .. zeek:field:: location :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The user specified location string.


   .. zeek:field:: message :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Additional informational string by the catch and release framework about this log-line.


   .. zeek:field:: plugin :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Plugin triggering the log entry.


   The record type that is used for representing and logging

Events
######
.. zeek:id:: NetControl::catch_release_add
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 161 161

   :Type: :zeek:type:`event` (a: :zeek:type:`addr`, location: :zeek:type:`string`)


.. zeek:id:: NetControl::catch_release_block_delete
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 160 160

   :Type: :zeek:type:`event` (a: :zeek:type:`addr`)


.. zeek:id:: NetControl::catch_release_block_new
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 159 159

   :Type: :zeek:type:`event` (a: :zeek:type:`addr`, b: :zeek:type:`NetControl::BlockInfo`)


.. zeek:id:: NetControl::catch_release_delete
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 162 162

   :Type: :zeek:type:`event` (a: :zeek:type:`addr`, reason: :zeek:type:`string`)


.. zeek:id:: NetControl::catch_release_encountered
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 163 163

   :Type: :zeek:type:`event` (a: :zeek:type:`addr`)


.. zeek:id:: NetControl::catch_release_forgotten
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 139 139

   :Type: :zeek:type:`event` (a: :zeek:type:`addr`, bi: :zeek:type:`NetControl::BlockInfo`)

   Event is raised when catch and release cases management of an IP address because no
   activity was seen within the watch_until period.
   

   :param a: The address that is no longer being managed.
   

   :param bi: The :zeek:see:`NetControl::BlockInfo` record containing information about the block.

.. zeek:id:: NetControl::log_netcontrol_catch_release
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 156 156

   :Type: :zeek:type:`event` (rec: :zeek:type:`NetControl::CatchReleaseInfo`)

   Event that can be handled to access the :zeek:type:`NetControl::CatchReleaseInfo`
   record as it is sent on to the logging framework.

Hooks
#####
.. zeek:id:: NetControl::log_policy_catch_release
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 12 12

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: NetControl::catch_release_seen
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 447 511

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`void`

   This function can be called to notify the catch and release script that activity by
   an IP address was seen. If the respective IP address is currently monitored by catch and
   release and not blocked, the block will be reinstated. See the documentation of watch_new_connection
   which events the catch and release functionality usually monitors for activity.
   

   :param a: The address that was seen and should be re-dropped if it is being watched.

.. zeek:id:: NetControl::drop_address_catch_release
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 353 419

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, location: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`NetControl::BlockInfo`

   Stops all packets involving an IP address from being forwarded. This function
   uses catch-and-release functionality, where the IP address is only dropped for
   a short amount of time that is incremented steadily when the IP is encountered
   again.
   
   In cluster mode, this function works on workers as well as the manager. On managers,
   the returned :zeek:see:`NetControl::BlockInfo` record will not contain the block ID,
   which will be assigned on the manager.
   

   :param a: The address to be dropped.
   

   :param t: How long to drop it, with 0 being indefinitely.
   

   :param location: An optional string describing where the drop was triggered.
   

   :returns: The :zeek:see:`NetControl::BlockInfo` record containing information about
            the inserted block.

.. zeek:id:: NetControl::get_catch_release_info
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 345 351

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`) : :zeek:type:`NetControl::BlockInfo`

   Get the :zeek:see:`NetControl::BlockInfo` record for an address currently blocked by catch and release.
   If the address is unknown to catch and release, the watch_until time will be set to 0.
   
   In cluster mode, this function works on the manager and workers. On workers, the data will
   lag slightly behind the manager; if you add a block, it will not be instantly available via
   this function.
   

   :param a: The address to get information about.
   

   :returns: The :zeek:see:`NetControl::BlockInfo` record containing information about
            the inserted block.

.. zeek:id:: NetControl::unblock_address_catch_release
   :source-code: policy/frameworks/netcontrol/catch-and-release.zeek 422 445

   :Type: :zeek:type:`function` (a: :zeek:type:`addr`, reason: :zeek:type:`string` :zeek:attr:`&default` = ``""`` :zeek:attr:`&optional`) : :zeek:type:`bool`

   Removes an address from being watched with catch and release. Returns true if the
   address was found and removed; returns false if it was unknown to catch and release.
   
   If the address is currently blocked, and the block was inserted by catch and release,
   the block is removed.
   

   :param a: The address to be unblocked.
   

   :param reason: A reason for the unblock.
   

   :returns: True if the address was unblocked.


