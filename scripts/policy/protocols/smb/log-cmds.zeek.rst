:tocdepth: 3

policy/protocols/smb/log-cmds.zeek
==================================
.. bro:namespace:: SMB

Load this script to generate an SMB command log, smb_cmd.log.
This is primarily useful for debugging.

:Namespace: SMB
:Imports: :doc:`base/protocols/smb </scripts/base/protocols/smb/index>`

Summary
~~~~~~~
Runtime Options
###############
=========================================================================== ====================================================
:bro:id:`SMB::ignored_command_statuses`: :bro:type:`set` :bro:attr:`&redef` The server response statuses which are *not* logged.
=========================================================================== ====================================================

Redefinitions
#############
===================================== =
:bro:type:`Log::ID`: :bro:type:`enum` 
===================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMB::ignored_command_statuses

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "MORE_PROCESSING_REQUIRED"
      }

   The server response statuses which are *not* logged.


