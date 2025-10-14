:tocdepth: 3

base/bif/plugins/Zeek_MySQL.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ======================================================================================================
:zeek:id:`mysql_command_request`: :zeek:type:`event` Generated for a command request from a MySQL client.
:zeek:id:`mysql_eof`: :zeek:type:`event`             Generated for a MySQL EOF packet.
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
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 16 16

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, command: :zeek:type:`count`, arg: :zeek:type:`string`)

   Generated for a command request from a MySQL client.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param command: The numerical code of the command issued.
   

   :param arg: The argument for the command (empty string if not provided).
   
   .. zeek:see:: mysql_error mysql_ok mysql_server_version mysql_handshake

.. zeek:id:: mysql_eof
   :source-code: base/protocols/mysql/main.zeek 115 132

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_intermediate: :zeek:type:`bool`)

   Generated for a MySQL EOF packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param is_intermediate: True if this is an EOF packet between the column definition and the rows, false if a final EOF.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_error
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, code: :zeek:type:`count`, msg: :zeek:type:`string`)

   Generated for an unsuccessful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param code: The error code.
   

   :param msg: Any extra details about the error (empty string if not provided).
   
   .. zeek:see:: mysql_command_request mysql_ok mysql_server_version mysql_handshake

.. zeek:id:: mysql_handshake
   :source-code: base/protocols/mysql/main.zeek 52 65

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, username: :zeek:type:`string`)

   Generated for a client handshake response packet, which includes the username the client is attempting
   to connect as.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param username: The username supplied by the client
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_server_version

.. zeek:id:: mysql_ok
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 44 44

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, affected_rows: :zeek:type:`count`)

   Generated for a successful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param affected_rows: The number of rows that were affected.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_result_row
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 70 70

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, row: :zeek:type:`string_vec`)

   Generated for each MySQL ResultsetRow response packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param row: The result row data.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake mysql_ok

.. zeek:id:: mysql_server_version
   :source-code: policy/protocols/mysql/software.zeek 14 20

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, ver: :zeek:type:`string`)

   Generated for the initial server handshake packet, which includes the MySQL server version.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param ver: The server version string.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_handshake


