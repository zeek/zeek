:tocdepth: 3

policy/protocols/smb/log-cmds.zeek
==================================
.. zeek:namespace:: SMB

Load this script to generate an SMB command log, smb_cmd.log.
This is primarily useful for debugging.

:Namespace: SMB
:Imports: :doc:`base/protocols/smb </scripts/base/protocols/smb/index>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================== ====================================================
:zeek:id:`SMB::ignored_command_statuses`: :zeek:type:`set` :zeek:attr:`&redef` The server response statuses which are *not* logged.
============================================================================== ====================================================

Redefinitions
#############
======================================= ===========================
:zeek:type:`Log::ID`: :zeek:type:`enum` 
                                        
                                        * :zeek:enum:`SMB::CMD_LOG`
======================================= ===========================

Hooks
#####
======================================================== =
:zeek:id:`SMB::log_policy`: :zeek:type:`Log::PolicyHook` 
======================================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMB::ignored_command_statuses
   :source-code: policy/protocols/smb/log-cmds.zeek 16 16

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "MORE_PROCESSING_REQUIRED"
         }


   The server response statuses which are *not* logged.

Hooks
#####
.. zeek:id:: SMB::log_policy
   :source-code: policy/protocols/smb/log-cmds.zeek 13 13

   :Type: :zeek:type:`Log::PolicyHook`



