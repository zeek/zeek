:tocdepth: 3

base/protocols/smb/main.zeek
============================
.. zeek:namespace:: SMB


:Namespace: SMB
:Imports: :doc:`base/protocols/smb/const-dos-error.zeek </scripts/base/protocols/smb/const-dos-error.zeek>`, :doc:`base/protocols/smb/const-nt-status.zeek </scripts/base/protocols/smb/const-nt-status.zeek>`, :doc:`base/protocols/smb/consts.zeek </scripts/base/protocols/smb/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================= ==================================
:zeek:id:`SMB::logged_file_actions`: :zeek:type:`set` :zeek:attr:`&redef` The file actions which are logged.
========================================================================= ==================================

Types
#####
=============================================== =======================================================
:zeek:type:`SMB::Action`: :zeek:type:`enum`     Abstracted actions for SMB file actions.
:zeek:type:`SMB::CmdInfo`: :zeek:type:`record`  This record is for the smb_cmd.log
:zeek:type:`SMB::FileInfo`: :zeek:type:`record` This record is for the smb_files.log
:zeek:type:`SMB::State`: :zeek:type:`record`    This record stores the SMB state of in-flight commands,
                                                the file and tree map of the connection.
:zeek:type:`SMB::TreeInfo`: :zeek:type:`record` This record is for the smb_mapping.log
=============================================== =======================================================

Redefinitions
#############
==================================================================== ============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`SMB::FileInfo`: :zeek:type:`record`                      
:zeek:type:`connection`: :zeek:type:`record`                         Everything below here is used internally in the SMB scripts.
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ============================================================

Functions
#########
=========================================================================== ====================================
:zeek:id:`SMB::set_current_file`: :zeek:type:`function` :zeek:attr:`&redef` This is an internally used function.
:zeek:id:`SMB::write_file_log`: :zeek:type:`function` :zeek:attr:`&redef`   This is an internally used function.
=========================================================================== ====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMB::logged_file_actions

   :Type: :zeek:type:`set` [:zeek:type:`SMB::Action`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

   ::

      {
         SMB::FILE_OPEN,
         SMB::PRINT_CLOSE,
         SMB::FILE_DELETE,
         SMB::FILE_RENAME,
         SMB::PRINT_OPEN
      }

   The file actions which are logged.

Types
#####
.. zeek:type:: SMB::Action

   :Type: :zeek:type:`enum`

      .. zeek:enum:: SMB::FILE_READ SMB::Action

      .. zeek:enum:: SMB::FILE_WRITE SMB::Action

      .. zeek:enum:: SMB::FILE_OPEN SMB::Action

      .. zeek:enum:: SMB::FILE_CLOSE SMB::Action

      .. zeek:enum:: SMB::FILE_DELETE SMB::Action

      .. zeek:enum:: SMB::FILE_RENAME SMB::Action

      .. zeek:enum:: SMB::FILE_SET_ATTRIBUTE SMB::Action

      .. zeek:enum:: SMB::PIPE_READ SMB::Action

      .. zeek:enum:: SMB::PIPE_WRITE SMB::Action

      .. zeek:enum:: SMB::PIPE_OPEN SMB::Action

      .. zeek:enum:: SMB::PIPE_CLOSE SMB::Action

      .. zeek:enum:: SMB::PRINT_READ SMB::Action

      .. zeek:enum:: SMB::PRINT_WRITE SMB::Action

      .. zeek:enum:: SMB::PRINT_OPEN SMB::Action

      .. zeek:enum:: SMB::PRINT_CLOSE SMB::Action

   Abstracted actions for SMB file actions.

.. zeek:type:: SMB::CmdInfo

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp of the command request.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID of the connection the request was sent over.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         ID of the connection the request was sent over.

      command: :zeek:type:`string` :zeek:attr:`&log`
         The command sent by the client.

      sub_command: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The subcommand sent by the client, if present.

      argument: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Command argument sent by the client, if any.

      status: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Server reply to the client's command.

      rtt: :zeek:type:`interval` :zeek:attr:`&log` :zeek:attr:`&optional`
         Round trip time from the request to the response.

      version: :zeek:type:`string` :zeek:attr:`&log`
         Version of SMB for the command.

      username: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Authenticated username, if available.

      tree: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         If this is related to a tree, this is the tree
         that was used for the current command.

      tree_service: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The type of tree (disk share, printer share, named pipe, etc.).

      referenced_file: :zeek:type:`SMB::FileInfo` :zeek:attr:`&log` :zeek:attr:`&optional`
         If the command referenced a file, store it here.

      referenced_tree: :zeek:type:`SMB::TreeInfo` :zeek:attr:`&optional`
         If the command referenced a tree, store it here.

      smb1_offered_dialects: :zeek:type:`string_vec` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smb/smb1-main.zeek` is loaded)

         Dialects offered by the client.

      smb2_offered_dialects: :zeek:type:`index_vec` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smb/smb2-main.zeek` is loaded)

         Dialects offered by the client.

   This record is for the smb_cmd.log

.. zeek:type:: SMB::FileInfo

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the file was first discovered.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID of the connection the file was sent over.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         ID of the connection the file was sent over.

      fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Unique ID of the file.

      action: :zeek:type:`SMB::Action` :zeek:attr:`&log` :zeek:attr:`&optional`
         Action this log record represents.

      path: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Path pulled from the tree this file was transferred to or from.

      name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Filename if one was seen.

      size: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Total size of the file.

      prev_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         If the rename action was seen, this will be
         the file's previous name.

      times: :zeek:type:`SMB::MACTimes` :zeek:attr:`&log` :zeek:attr:`&optional`
         Last time this file was modified.

      fid: :zeek:type:`count` :zeek:attr:`&optional`
         ID referencing this file.

      uuid: :zeek:type:`string` :zeek:attr:`&optional`
         UUID referencing this file if DCE/RPC.

   This record is for the smb_files.log

.. zeek:type:: SMB::State

   :Type: :zeek:type:`record`

      current_cmd: :zeek:type:`SMB::CmdInfo` :zeek:attr:`&optional`
         A reference to the current command.

      current_file: :zeek:type:`SMB::FileInfo` :zeek:attr:`&optional`
         A reference to the current file.

      current_tree: :zeek:type:`SMB::TreeInfo` :zeek:attr:`&optional`
         A reference to the current tree.

      pending_cmds: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`SMB::CmdInfo` :zeek:attr:`&optional`
         Indexed on MID to map responses to requests.

      fid_map: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`SMB::FileInfo` :zeek:attr:`&optional`
         File map to retrieve file information based on the file ID.

      tid_map: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`SMB::TreeInfo` :zeek:attr:`&optional`
         Tree map to retrieve tree information based on the tree ID.

      uid_map: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string` :zeek:attr:`&optional`
         User map to retrieve user name based on the user ID.

      pipe_map: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string` :zeek:attr:`&optional`
         Pipe map to retrieve UUID based on the file ID of a pipe.

      recent_files: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&default` = ``{  }`` :zeek:attr:`&optional` :zeek:attr:`&read_expire` = ``3.0 mins``
         A set of recent files to avoid logging the same
         files over and over in the smb files log.
         This only applies to files seen in a single connection.

   This record stores the SMB state of in-flight commands,
   the file and tree map of the connection.

.. zeek:type:: SMB::TreeInfo

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         Time when the tree was mapped.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID of the connection the tree was mapped over.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         ID of the connection the tree was mapped over.

      path: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Name of the tree path.

      service: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The type of resource of the tree (disk share, printer share, named pipe, etc.).

      native_file_system: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         File system of the tree.

      share_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``"DISK"`` :zeek:attr:`&optional`
         If this is SMB2, a share type will be included.  For SMB1,
         the type of share will be deduced and included as well.

   This record is for the smb_mapping.log

Functions
#########
.. zeek:id:: SMB::set_current_file

   :Type: :zeek:type:`function` (smb_state: :zeek:type:`SMB::State`, file_id: :zeek:type:`count`) : :zeek:type:`void`
   :Attributes: :zeek:attr:`&redef`

   This is an internally used function.

.. zeek:id:: SMB::write_file_log

   :Type: :zeek:type:`function` (state: :zeek:type:`SMB::State`) : :zeek:type:`void`
   :Attributes: :zeek:attr:`&redef`

   This is an internally used function.


