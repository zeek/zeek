:tocdepth: 3

base/protocols/smb/main.bro
===========================
.. bro:namespace:: SMB


:Namespace: SMB
:Imports: :doc:`base/protocols/smb/const-dos-error.bro </scripts/base/protocols/smb/const-dos-error.bro>`, :doc:`base/protocols/smb/const-nt-status.bro </scripts/base/protocols/smb/const-nt-status.bro>`, :doc:`base/protocols/smb/consts.bro </scripts/base/protocols/smb/consts.bro>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================== ==================================
:bro:id:`SMB::logged_file_actions`: :bro:type:`set` :bro:attr:`&redef` The file actions which are logged.
====================================================================== ==================================

Types
#####
============================================= =======================================================
:bro:type:`SMB::Action`: :bro:type:`enum`     Abstracted actions for SMB file actions.
:bro:type:`SMB::CmdInfo`: :bro:type:`record`  This record is for the smb_cmd.log
:bro:type:`SMB::FileInfo`: :bro:type:`record` This record is for the smb_files.log
:bro:type:`SMB::State`: :bro:type:`record`    This record stores the SMB state of in-flight commands,
                                              the file and tree map of the connection.
:bro:type:`SMB::TreeInfo`: :bro:type:`record` This record is for the smb_mapping.log
============================================= =======================================================

Redefinitions
#############
================================================================= ============================================================
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`SMB::FileInfo`: :bro:type:`record`                     
:bro:type:`connection`: :bro:type:`record`                        Everything below here is used internally in the SMB scripts.
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= ============================================================

Functions
#########
======================================================================== ====================================
:bro:id:`SMB::set_current_file`: :bro:type:`function` :bro:attr:`&redef` This is an internally used function.
:bro:id:`SMB::write_file_log`: :bro:type:`function` :bro:attr:`&redef`   This is an internally used function.
======================================================================== ====================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMB::logged_file_actions

   :Type: :bro:type:`set` [:bro:type:`SMB::Action`]
   :Attributes: :bro:attr:`&redef`
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
.. bro:type:: SMB::Action

   :Type: :bro:type:`enum`

      .. bro:enum:: SMB::FILE_READ SMB::Action

      .. bro:enum:: SMB::FILE_WRITE SMB::Action

      .. bro:enum:: SMB::FILE_OPEN SMB::Action

      .. bro:enum:: SMB::FILE_CLOSE SMB::Action

      .. bro:enum:: SMB::FILE_DELETE SMB::Action

      .. bro:enum:: SMB::FILE_RENAME SMB::Action

      .. bro:enum:: SMB::FILE_SET_ATTRIBUTE SMB::Action

      .. bro:enum:: SMB::PIPE_READ SMB::Action

      .. bro:enum:: SMB::PIPE_WRITE SMB::Action

      .. bro:enum:: SMB::PIPE_OPEN SMB::Action

      .. bro:enum:: SMB::PIPE_CLOSE SMB::Action

      .. bro:enum:: SMB::PRINT_READ SMB::Action

      .. bro:enum:: SMB::PRINT_WRITE SMB::Action

      .. bro:enum:: SMB::PRINT_OPEN SMB::Action

      .. bro:enum:: SMB::PRINT_CLOSE SMB::Action

   Abstracted actions for SMB file actions.

.. bro:type:: SMB::CmdInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp of the command request.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID of the connection the request was sent over.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         ID of the connection the request was sent over.

      command: :bro:type:`string` :bro:attr:`&log`
         The command sent by the client.

      sub_command: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The subcommand sent by the client, if present.

      argument: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Command argument sent by the client, if any.

      status: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Server reply to the client's command.

      rtt: :bro:type:`interval` :bro:attr:`&log` :bro:attr:`&optional`
         Round trip time from the request to the response.

      version: :bro:type:`string` :bro:attr:`&log`
         Version of SMB for the command.

      username: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Authenticated username, if available.

      tree: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         If this is related to a tree, this is the tree
         that was used for the current command.

      tree_service: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The type of tree (disk share, printer share, named pipe, etc.).

      referenced_file: :bro:type:`SMB::FileInfo` :bro:attr:`&log` :bro:attr:`&optional`
         If the command referenced a file, store it here.

      referenced_tree: :bro:type:`SMB::TreeInfo` :bro:attr:`&optional`
         If the command referenced a tree, store it here.

      smb1_offered_dialects: :bro:type:`string_vec` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smb/smb1-main.bro` is loaded)

         Dialects offered by the client.

      smb2_offered_dialects: :bro:type:`index_vec` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smb/smb2-main.bro` is loaded)

         Dialects offered by the client.

   This record is for the smb_cmd.log

.. bro:type:: SMB::FileInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time when the file was first discovered.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID of the connection the file was sent over.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         ID of the connection the file was sent over.

      fuid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Unique ID of the file.

      action: :bro:type:`SMB::Action` :bro:attr:`&log` :bro:attr:`&optional`
         Action this log record represents.

      path: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Path pulled from the tree this file was transferred to or from.

      name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Filename if one was seen.

      size: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Total size of the file.

      prev_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         If the rename action was seen, this will be
         the file's previous name.

      times: :bro:type:`SMB::MACTimes` :bro:attr:`&log` :bro:attr:`&optional`
         Last time this file was modified.

      fid: :bro:type:`count` :bro:attr:`&optional`
         ID referencing this file.

      uuid: :bro:type:`string` :bro:attr:`&optional`
         UUID referencing this file if DCE/RPC.

   This record is for the smb_files.log

.. bro:type:: SMB::State

   :Type: :bro:type:`record`

      current_cmd: :bro:type:`SMB::CmdInfo` :bro:attr:`&optional`
         A reference to the current command.

      current_file: :bro:type:`SMB::FileInfo` :bro:attr:`&optional`
         A reference to the current file.

      current_tree: :bro:type:`SMB::TreeInfo` :bro:attr:`&optional`
         A reference to the current tree.

      pending_cmds: :bro:type:`table` [:bro:type:`count`] of :bro:type:`SMB::CmdInfo` :bro:attr:`&optional`
         Indexed on MID to map responses to requests.

      fid_map: :bro:type:`table` [:bro:type:`count`] of :bro:type:`SMB::FileInfo` :bro:attr:`&optional`
         File map to retrieve file information based on the file ID.

      tid_map: :bro:type:`table` [:bro:type:`count`] of :bro:type:`SMB::TreeInfo` :bro:attr:`&optional`
         Tree map to retrieve tree information based on the tree ID.

      uid_map: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string` :bro:attr:`&optional`
         User map to retrieve user name based on the user ID.

      pipe_map: :bro:type:`table` [:bro:type:`count`] of :bro:type:`string` :bro:attr:`&optional`
         Pipe map to retrieve UUID based on the file ID of a pipe.

      recent_files: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&default` = ``{  }`` :bro:attr:`&optional` :bro:attr:`&read_expire` = ``3.0 mins``
         A set of recent files to avoid logging the same
         files over and over in the smb files log.
         This only applies to files seen in a single connection.

   This record stores the SMB state of in-flight commands,
   the file and tree map of the connection.

.. bro:type:: SMB::TreeInfo

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         Time when the tree was mapped.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID of the connection the tree was mapped over.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         ID of the connection the tree was mapped over.

      path: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Name of the tree path.

      service: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The type of resource of the tree (disk share, printer share, named pipe, etc.).

      native_file_system: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         File system of the tree.

      share_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&default` = ``"DISK"`` :bro:attr:`&optional`
         If this is SMB2, a share type will be included.  For SMB1,
         the type of share will be deduced and included as well.

   This record is for the smb_mapping.log

Functions
#########
.. bro:id:: SMB::set_current_file

   :Type: :bro:type:`function` (smb_state: :bro:type:`SMB::State`, file_id: :bro:type:`count`) : :bro:type:`void`
   :Attributes: :bro:attr:`&redef`

   This is an internally used function.

.. bro:id:: SMB::write_file_log

   :Type: :bro:type:`function` (state: :bro:type:`SMB::State`) : :bro:type:`void`
   :Attributes: :bro:attr:`&redef`

   This is an internally used function.


