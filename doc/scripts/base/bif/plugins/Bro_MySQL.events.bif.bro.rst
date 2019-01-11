:tocdepth: 3

base/bif/plugins/Bro_MySQL.events.bif.bro
=========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== ======================================================================================================
:bro:id:`mysql_command_request`: :bro:type:`event` Generated for a command request from a MySQL client.
:bro:id:`mysql_error`: :bro:type:`event`           Generated for an unsuccessful MySQL response.
:bro:id:`mysql_handshake`: :bro:type:`event`       Generated for a client handshake response packet, which includes the username the client is attempting
                                                   to connect as.
:bro:id:`mysql_ok`: :bro:type:`event`              Generated for a successful MySQL response.
:bro:id:`mysql_result_row`: :bro:type:`event`      Generated for each MySQL ResultsetRow response packet.
:bro:id:`mysql_server_version`: :bro:type:`event`  Generated for the initial server handshake packet, which includes the MySQL server version.
================================================== ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: mysql_command_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, command: :bro:type:`count`, arg: :bro:type:`string`)

   Generated for a command request from a MySQL client.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :command: The numerical code of the command issued.
   

   :arg: The argument for the command (empty string if not provided).
   
   .. bro:see:: mysql_error mysql_ok mysql_server_version mysql_handshake

.. bro:id:: mysql_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, code: :bro:type:`count`, msg: :bro:type:`string`)

   Generated for an unsuccessful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :code: The error code.
   

   :msg: Any extra details about the error (empty string if not provided).
   
   .. bro:see:: mysql_command_request mysql_ok mysql_server_version mysql_handshake

.. bro:id:: mysql_handshake

   :Type: :bro:type:`event` (c: :bro:type:`connection`, username: :bro:type:`string`)

   Generated for a client handshake response packet, which includes the username the client is attempting
   to connect as.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :username: The username supplied by the client
   
   .. bro:see:: mysql_command_request mysql_error mysql_ok mysql_server_version

.. bro:id:: mysql_ok

   :Type: :bro:type:`event` (c: :bro:type:`connection`, affected_rows: :bro:type:`count`)

   Generated for a successful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :affected_rows: The number of rows that were affected.
   
   .. bro:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. bro:id:: mysql_result_row

   :Type: :bro:type:`event` (c: :bro:type:`connection`, row: :bro:type:`string_vec`)

   Generated for each MySQL ResultsetRow response packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :row: The result row data.
   
   .. bro:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake mysql_ok

.. bro:id:: mysql_server_version

   :Type: :bro:type:`event` (c: :bro:type:`connection`, ver: :bro:type:`string`)

   Generated for the initial server handshake packet, which includes the MySQL server version.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :c: The connection.
   

   :ver: The server version string.
   
   .. bro:see:: mysql_command_request mysql_error mysql_ok mysql_handshake


