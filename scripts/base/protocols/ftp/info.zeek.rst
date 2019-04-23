:tocdepth: 3

base/protocols/ftp/info.zeek
============================
.. zeek:namespace:: FTP

Defines data structures for tracking and logging FTP sessions.

:Namespace: FTP
:Imports: :doc:`base/protocols/ftp/utils-commands.zeek </scripts/base/protocols/ftp/utils-commands.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== ==========================================================
:zeek:id:`FTP::default_capture_password`: :zeek:type:`bool` :zeek:attr:`&redef` This setting changes if passwords used in FTP sessions are
                                                                                captured or not.
=============================================================================== ==========================================================

Types
#####
========================================================== ==============================================
:zeek:type:`FTP::ExpectedDataChannel`: :zeek:type:`record` The expected endpoints of an FTP data channel.
:zeek:type:`FTP::Info`: :zeek:type:`record`                
========================================================== ==============================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: FTP::default_capture_password

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   This setting changes if passwords used in FTP sessions are
   captured or not.

Types
#####
.. zeek:type:: FTP::ExpectedDataChannel

   :Type: :zeek:type:`record`

      passive: :zeek:type:`bool` :zeek:attr:`&log`
         Whether PASV mode is toggled for control channel.

      orig_h: :zeek:type:`addr` :zeek:attr:`&log`
         The host that will be initiating the data connection.

      resp_h: :zeek:type:`addr` :zeek:attr:`&log`
         The host that will be accepting the data connection.

      resp_p: :zeek:type:`port` :zeek:attr:`&log`
         The port at which the acceptor is listening for the data
         connection.

   The expected endpoints of an FTP data channel.

.. zeek:type:: FTP::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the command was sent.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      user: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``"<unknown>"`` :zeek:attr:`&optional`
         User name for the current FTP session.

      password: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Password for the current FTP session if captured.

      command: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Command given by the client.

      arg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Argument for the command if one is given.

      mime_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Sniffed mime type of file.

      file_size: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Size of the file if the command indicates a file transfer.

      reply_code: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Reply code from the server in response to the command.

      reply_msg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Reply message from the server in response to the command.

      data_channel: :zeek:type:`FTP::ExpectedDataChannel` :zeek:attr:`&log` :zeek:attr:`&optional`
         Expected FTP data channel.

      cwd: :zeek:type:`string` :zeek:attr:`&default` = ``"."`` :zeek:attr:`&optional`
         Current working directory that this session is in.  By making
         the default value '.', we can indicate that unless something
         more concrete is discovered that the existing but unknown
         directory is ok to use.

      cmdarg: :zeek:type:`FTP::CmdArg` :zeek:attr:`&optional`
         Command that is currently waiting for a response.

      pending_commands: :zeek:type:`FTP::PendingCmds`
         Queue for commands that have been sent but not yet responded
         to are tracked here.

      passive: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicates if the session is in active or passive mode.

      capture_password: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`FTP::default_capture_password` :zeek:attr:`&optional`
         Determines if the password will be captured for this request.

      fuid: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         (present if :doc:`/scripts/base/protocols/ftp/files.zeek` is loaded)

         File unique ID.

      last_auth_requested: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/ftp/gridftp.zeek` is loaded)




