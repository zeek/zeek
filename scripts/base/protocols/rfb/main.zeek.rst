:tocdepth: 3

base/protocols/rfb/main.zeek
============================
.. bro:namespace:: RFB


:Namespace: RFB

Summary
~~~~~~~
Types
#####
========================================= =========================================================
:bro:type:`RFB::Info`: :bro:type:`record` The record type which contains the fields of the RFB log.
========================================= =========================================================

Redefinitions
#############
========================================== =
:bro:type:`Log::ID`: :bro:type:`enum`      
:bro:type:`connection`: :bro:type:`record` 
========================================== =

Events
######
========================================= =
:bro:id:`RFB::log_rfb`: :bro:type:`event` 
========================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. bro:type:: RFB::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      client_major_version: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Major version of the client.

      client_minor_version: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Minor version of the client.

      server_major_version: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Major version of the server.

      server_minor_version: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Minor version of the server.

      authentication_method: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Identifier of authentication method used.

      auth: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Whether or not authentication was successful.

      share_flag: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Whether the client has an exclusive or a shared session.

      desktop_name: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Name of the screen that is being shared.

      width: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Width of the screen that is being shared.

      height: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Height of the screen that is being shared.

      done: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Internally used value to determine if this connection
         has already been logged.

   The record type which contains the fields of the RFB log.

Events
######
.. bro:id:: RFB::log_rfb

   :Type: :bro:type:`event` (rec: :bro:type:`RFB::Info`)



