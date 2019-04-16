:tocdepth: 3

base/protocols/irc/main.zeek
============================
.. bro:namespace:: IRC

Implements the core IRC analysis support.  The logging model is to log
IRC commands along with the associated response and some additional 
metadata about the connection if it's available.

:Namespace: IRC

Summary
~~~~~~~
Types
#####
========================================= =
:bro:type:`IRC::Info`: :bro:type:`record` 
========================================= =

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
========================================= ====================================================================
:bro:id:`IRC::irc_log`: :bro:type:`event` Event that can be handled to access the IRC record as it is sent on 
                                          to the logging framework.
========================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: IRC::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp when the command was seen.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      nick: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Nickname given for the connection.

      user: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Username given for the connection.

      command: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Command given by the client.

      value: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value for the command given by the client.

      addl: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Any additional data for the command.

      dcc_file_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

         DCC filename requested.

      dcc_file_size: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

         Size of the DCC transfer as indicated by the sender.

      dcc_mime_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/dcc-send.zeek` is loaded)

         Sniffed mime type of the file.

      fuid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/irc/files.zeek` is loaded)

         File unique ID.


Events
######
.. bro:id:: IRC::irc_log

   :Type: :bro:type:`event` (rec: :bro:type:`IRC::Info`)

   Event that can be handled to access the IRC record as it is sent on 
   to the logging framework.


