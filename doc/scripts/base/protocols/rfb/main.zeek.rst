:tocdepth: 3

base/protocols/rfb/main.zeek
============================
.. zeek:namespace:: RFB


:Namespace: RFB
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`

Summary
~~~~~~~
Types
#####
=========================================== =========================================================
:zeek:type:`RFB::Info`: :zeek:type:`record` The record type which contains the fields of the RFB log.
=========================================== =========================================================

Redefinitions
#############
============================================ ====================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`RFB::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               rfb: :zeek:type:`RFB::Info` :zeek:attr:`&optional`
============================================ ====================================================

Events
######
=========================================== =
:zeek:id:`RFB::log_rfb`: :zeek:type:`event` 
=========================================== =

Hooks
#####
============================================================ ======================
:zeek:id:`RFB::finalize_rfb`: :zeek:type:`Conn::RemovalHook` RFB finalization hook.
:zeek:id:`RFB::log_policy`: :zeek:type:`Log::PolicyHook`     
============================================================ ======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Types
#####
.. zeek:type:: RFB::Info
   :source-code: base/protocols/rfb/main.zeek 11 45

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the event happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      client_major_version: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Major version of the client.

      client_minor_version: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Minor version of the client.

      server_major_version: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Major version of the server.

      server_minor_version: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Minor version of the server.

      authentication_method: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Identifier of authentication method used.

      auth: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Whether or not authentication was successful.

      share_flag: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Whether the client has an exclusive or a shared session.

      desktop_name: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Name of the screen that is being shared.

      width: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Width of the screen that is being shared.

      height: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Height of the screen that is being shared.

      done: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Internally used value to determine if this connection
         has already been logged.

   The record type which contains the fields of the RFB log.

Events
######
.. zeek:id:: RFB::log_rfb
   :source-code: base/protocols/rfb/main.zeek 47 47

   :Type: :zeek:type:`event` (rec: :zeek:type:`RFB::Info`)


Hooks
#####
.. zeek:id:: RFB::finalize_rfb
   :source-code: base/protocols/rfb/main.zeek 162 168

   :Type: :zeek:type:`Conn::RemovalHook`

   RFB finalization hook.  Remaining RFB info may get logged when it's called.

.. zeek:id:: RFB::log_policy
   :source-code: base/protocols/rfb/main.zeek 8 8

   :Type: :zeek:type:`Log::PolicyHook`



