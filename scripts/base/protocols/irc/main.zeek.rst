:tocdepth: 3

base/protocols/irc/main.zeek
============================
.. zeek:namespace:: IRC

Implements the core IRC analysis support.  The logging model is to log
IRC commands along with the associated response and some additional 
metadata about the connection if it's available.

:Namespace: IRC

Summary
~~~~~~~
Types
#####
=========================================== =
:zeek:type:`IRC::Info`: :zeek:type:`record` 
=========================================== =

Redefinitions
#############
==================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =

Events
######
=========================================== ====================================================================
:zeek:id:`IRC::irc_log`: :zeek:type:`event` Event that can be handled to access the IRC record as it is sent on 
                                            to the logging framework.
=========================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: IRC::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp when the command was seen.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      nick: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Nickname given for the connection.

      user: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Username given for the connection.

      command: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Command given by the client.

      value: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value for the command given by the client.

      addl: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Any additional data for the command.

      dcc_file_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

         DCC filename requested.

      dcc_file_size: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

         Size of the DCC transfer as indicated by the sender.

      dcc_mime_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

         Sniffed mime type of the file.

      fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/files.zeek` is loaded)

         File unique ID.


Events
######
.. zeek:id:: IRC::irc_log

   :Type: :zeek:type:`event` (rec: :zeek:type:`IRC::Info`)

   Event that can be handled to access the IRC record as it is sent on 
   to the logging framework.


