:tocdepth: 3

base/protocols/ftp/info.zeek
============================
.. bro:namespace:: FTP

Defines data structures for tracking and logging FTP sessions.

:Namespace: FTP
:Imports: :doc:`base/protocols/ftp/utils-commands.zeek </scripts/base/protocols/ftp/utils-commands.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ ==========================================================
:bro:id:`FTP::default_capture_password`: :bro:type:`bool` :bro:attr:`&redef` This setting changes if passwords used in FTP sessions are
                                                                             captured or not.
============================================================================ ==========================================================

Types
#####
======================================================== ==============================================
:bro:type:`FTP::ExpectedDataChannel`: :bro:type:`record` The expected endpoints of an FTP data channel.
:bro:type:`FTP::Info`: :bro:type:`record`                
======================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: FTP::default_capture_password

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   This setting changes if passwords used in FTP sessions are
   captured or not.

Types
#####
.. bro:type:: FTP::ExpectedDataChannel

   :Type: :bro:type:`record`

      passive: :bro:type:`bool` :bro:attr:`&log`
         Whether PASV mode is toggled for control channel.

      orig_h: :bro:type:`addr` :bro:attr:`&log`
         The host that will be initiating the data connection.

      resp_h: :bro:type:`addr` :bro:attr:`&log`
         The host that will be accepting the data connection.

      resp_p: :bro:type:`port` :bro:attr:`&log`
         The port at which the acceptor is listening for the data
         connection.

   The expected endpoints of an FTP data channel.

.. bro:type:: FTP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time when the command was sent.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      user: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&default` = ``"<unknown>"`` :bro:attr:`&optional`
         User name for the current FTP session.

      password: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Password for the current FTP session if captured.

      command: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Command given by the client.

      arg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Argument for the command if one is given.

      mime_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Sniffed mime type of file.

      file_size: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Size of the file if the command indicates a file transfer.

      reply_code: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Reply code from the server in response to the command.

      reply_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Reply message from the server in response to the command.

      data_channel: :bro:type:`FTP::ExpectedDataChannel` :bro:attr:`&log` :bro:attr:`&optional`
         Expected FTP data channel.

      cwd: :bro:type:`string` :bro:attr:`&default` = ``"."`` :bro:attr:`&optional`
         Current working directory that this session is in.  By making
         the default value '.', we can indicate that unless something
         more concrete is discovered that the existing but unknown
         directory is ok to use.

      cmdarg: :bro:type:`FTP::CmdArg` :bro:attr:`&optional`
         Command that is currently waiting for a response.

      pending_commands: :bro:type:`FTP::PendingCmds`
         Queue for commands that have been sent but not yet responded
         to are tracked here.

      passive: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Indicates if the session is in active or passive mode.

      capture_password: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`FTP::default_capture_password` :bro:attr:`&optional`
         Determines if the password will be captured for this request.

      fuid: :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         (present if :doc:`/scripts/base/protocols/ftp/files.zeek` is loaded)

         File unique ID.

      last_auth_requested: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/gridftp.zeek` is loaded)




