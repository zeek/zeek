:tocdepth: 3

base/protocols/krb/main.zeek
============================
.. zeek:namespace:: KRB

Implements base functionality for KRB analysis. Generates the kerberos.log
file.

:Namespace: KRB
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/protocols/krb/consts.zeek </scripts/base/protocols/krb/consts.zeek>`

Summary
~~~~~~~
Runtime Options
###############
==================================================================== =======================================================
:zeek:id:`KRB::ignored_errors`: :zeek:type:`set` :zeek:attr:`&redef` The server response error texts which are *not* logged.
==================================================================== =======================================================

Types
#####
=========================================== =
:zeek:type:`KRB::Info`: :zeek:type:`record` 
=========================================== =

Redefinitions
#############
==================================================================== ====================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`KRB::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       krb: :zeek:type:`KRB::Info` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== ====================================================

Events
######
=========================================== ===================================================================
:zeek:id:`KRB::log_krb`: :zeek:type:`event` Event that can be handled to access the KRB record as it is sent on
                                            to the logging framework.
=========================================== ===================================================================

Hooks
#####
============================================================ ===========================
:zeek:id:`KRB::finalize_krb`: :zeek:type:`Conn::RemovalHook` Kerberos finalization hook.
:zeek:id:`KRB::log_policy`: :zeek:type:`Log::PolicyHook`     
============================================================ ===========================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: KRB::ignored_errors
   :source-code: base/protocols/krb/main.zeek 54 54

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "NEEDED_PREAUTH",
            "Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ"
         }


   The server response error texts which are *not* logged.

Types
#####
.. zeek:type:: KRB::Info
   :source-code: base/protocols/krb/main.zeek 14 51

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the event happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      request_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Request type - Authentication Service ("AS") or
         Ticket Granting Service ("TGS")

      client: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Client

      service: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Service

      success: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Request result

      error_code: :zeek:type:`count` :zeek:attr:`&optional`
         Error code

      error_msg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Error message

      from: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         Ticket valid from

      till: :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`
         Ticket valid till

      cipher: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Ticket encryption type

      forwardable: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Forwardable ticket requested

      renewable: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`
         Renewable ticket requested

      logged: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         We've already logged this

      client_cert: :zeek:type:`Files::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

         Client certificate

      client_cert_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

         Subject of client certificate, if any

      client_cert_fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

         File unique ID of client cert, if any

      server_cert: :zeek:type:`Files::Info` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

         Server certificate

      server_cert_subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

         Subject of server certificate, if any

      server_cert_fuid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

         File unique ID of server cert, if any

      auth_ticket: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/krb/ticket-logging.zeek` is loaded)

         Hash of ticket used to authorize request/transaction

      new_ticket: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/krb/ticket-logging.zeek` is loaded)

         Hash of ticket returned by the KDC


Events
######
.. zeek:id:: KRB::log_krb
   :source-code: base/protocols/krb/main.zeek 68 68

   :Type: :zeek:type:`event` (rec: :zeek:type:`KRB::Info`)

   Event that can be handled to access the KRB record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: KRB::finalize_krb
   :source-code: base/protocols/krb/main.zeek 71 71

   :Type: :zeek:type:`Conn::RemovalHook`

   Kerberos finalization hook.  Remaining Kerberos info may get logged when it's called.

.. zeek:id:: KRB::log_policy
   :source-code: base/protocols/krb/main.zeek 12 12

   :Type: :zeek:type:`Log::PolicyHook`



