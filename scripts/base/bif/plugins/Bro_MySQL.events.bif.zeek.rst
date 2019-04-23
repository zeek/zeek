:tocdepth: 3

base/bif/plugins/Bro_MySQL.events.bif.zeek
==========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ======================================================================================================
:zeek:id:`mysql_command_request`: :zeek:type:`event` Generated for a command request from a MySQL client.
:zeek:id:`mysql_error`: :zeek:type:`event`           Generated for an unsuccessful MySQL response.
:zeek:id:`mysql_handshake`: :zeek:type:`event`       Generated for a client handshake response packet, which includes the username the client is attempting
                                                     to connect as.
:zeek:id:`mysql_ok`: :zeek:type:`event`              Generated for a successful MySQL response.
:zeek:id:`mysql_result_row`: :zeek:type:`event`      Generated for each MySQL ResultsetRow response packet.
:zeek:id:`mysql_server_version`: :zeek:type:`event`  Generated for the initial server handshake packet, which includes the MySQL server version.
==================================================== ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: mysql_command_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, command: :zeek:type:`count`, arg: :zeek:type:`string`)

   Generated for a command request from a MySQL client.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :command: The numerical code of the command issued.
   

   :arg: The argument for the command (empty string if not provided).
   
   .. zeek:see:: mysql_error mysql_ok mysql_server_version mysql_handshake

.. zeek:id:: mysql_error

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`, msg: :zeek:type:`string`)

   Generated for an unsuccessful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :code: The error code.
   

   :msg: Any extra details about the error (empty string if not provided).
   
   .. zeek:see:: mysql_command_request mysql_ok mysql_server_version mysql_handshake

.. zeek:id:: mysql_handshake

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, username: :zeek:type:`string`)

   Generated for a client handshake response packet, which includes the username the client is attempting
   to connect as.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :username: The username supplied by the client
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_server_version

.. zeek:id:: mysql_ok

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, affected_rows: :zeek:type:`count`)

   Generated for a successful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :affected_rows: The number of rows that were affected.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_result_row

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, row: :zeek:type:`string_vec`)

   Generated for each MySQL ResultsetRow response packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :row: The result row data.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake mysql_ok

.. zeek:id:: mysql_server_version

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ver: :zeek:type:`string`)

   Generated for the initial server handshake packet, which includes the MySQL server version.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :ver: The server version string.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_handshake


