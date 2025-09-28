:tocdepth: 3

base/bif/plugins/Zeek_MySQL.events.bif.zeek
===========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
======================================================== ======================================================================================================
:zeek:id:`mysql_auth_more_data`: :zeek:type:`event`      Generated for opaque authentication data exchanged between client and server
                                                         after the client's handshake packet, but before the server replied with
                                                         an OK_Packet
:zeek:id:`mysql_auth_plugin`: :zeek:type:`event`         Generated for information about plugin authentication within handshake packets.
:zeek:id:`mysql_auth_switch_request`: :zeek:type:`event` Generated for a server packet with an auth switch request.
:zeek:id:`mysql_change_user`: :zeek:type:`event`         Generated for a change user command from a MySQL client.
:zeek:id:`mysql_command_request`: :zeek:type:`event`     Generated for a command request from a MySQL client.
:zeek:id:`mysql_eof`: :zeek:type:`event`                 Generated for a MySQL EOF packet.
:zeek:id:`mysql_error`: :zeek:type:`event`               Generated for an unsuccessful MySQL response.
:zeek:id:`mysql_handshake`: :zeek:type:`event`           Generated for a client handshake response packet, which includes the username the client is attempting
                                                         to connect as.
:zeek:id:`mysql_ok`: :zeek:type:`event`                  Generated for a successful MySQL response.
:zeek:id:`mysql_result_row`: :zeek:type:`event`          Generated for each MySQL ResultsetRow response packet.
:zeek:id:`mysql_server_version`: :zeek:type:`event`      Generated for the initial server handshake packet, which includes the MySQL server version.
:zeek:id:`mysql_ssl_request`: :zeek:type:`event`         Generated for a short client handshake response packet with the CLIENT_SSL
                                                         flag set.
======================================================== ======================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: mysql_auth_more_data
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 166 166

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, data: :zeek:type:`string`)

   Generated for opaque authentication data exchanged between client and server
   after the client's handshake packet, but before the server replied with
   an OK_Packet
   
   Data is specific to the plugin auth mechanism used by client and server.
   

   :param c: The connection.
   

   :param is_orig: True if this is from the client, false if from the server.
   

   :param data: More authentication data.
   
   .. zeek:see:: mysql_handshake mysql_auth_switch_request

.. zeek:id:: mysql_auth_plugin
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 138 138

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, name: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for information about plugin authentication within handshake packets.
   

   :param c: The connection.
   

   :param is_orig: True if this is from the client, false if from the server.
   

   :param name: Name of the authentication plugin.
   

   :param data: The initial auth data. From the server, it is the concatenation of
         auth_plugin_data_part_1 and auth_plugin_data_part_2 in the handshake.
         For the client it is the auth_response in the handshake response.
   
   .. zeek:see:: mysql_handshake mysql_auth_switch_request mysql_auth_more_data

.. zeek:id:: mysql_auth_switch_request
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 150 150

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, name: :zeek:type:`string`, data: :zeek:type:`string`)

   Generated for a server packet with an auth switch request.
   

   :param c: The connection.
   

   :param name: The plugin name.
   

   :param data: Initial authentication data for the plugin.
   
   .. zeek:see:: mysql_handshake mysql_auth_more_data

.. zeek:id:: mysql_change_user
   :source-code: base/protocols/mysql/main.zeek 87 90

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, username: :zeek:type:`string`)

   Generated for a change user command from a MySQL client.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param username: The username supplied by the client
   
   .. zeek:see:: mysql_error mysql_ok mysql_server_version mysql_handshake

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
   :source-code: base/protocols/mysql/main.zeek 120 137

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_intermediate: :zeek:type:`bool`)

   Generated for a MySQL EOF packet.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param is_intermediate: True if this is an EOF packet between the column definition and the rows, false if a final EOF.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_error
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 44 44

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
   
   .. zeek:see:: mysql_command_request mysql_error mysql_ok mysql_server_version mysql_ssl_request

.. zeek:id:: mysql_ok
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 57 57

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, affected_rows: :zeek:type:`count`)

   Generated for a successful MySQL response.
   
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   

   :param affected_rows: The number of rows that were affected.
   
   .. zeek:see:: mysql_command_request mysql_error mysql_server_version mysql_handshake

.. zeek:id:: mysql_result_row
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 83 83

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

.. zeek:id:: mysql_ssl_request
   :source-code: base/bif/plugins/Zeek_MySQL.events.bif.zeek 122 122

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated for a short client handshake response packet with the CLIENT_SSL
   flag set. Usually the client will initiate a TLS handshake afterwards.
   See the MySQL `documentation <http://dev.mysql.com/doc/internals/en/client-server-protocol.html>`__
   for more information about the MySQL protocol.
   

   :param c: The connection.
   
   .. zeek:see:: mysql_handshake


