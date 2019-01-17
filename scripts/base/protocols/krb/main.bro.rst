:tocdepth: 3

base/protocols/krb/main.bro
===========================
.. bro:namespace:: KRB

Implements base functionality for KRB analysis. Generates the kerberos.log
file.

:Namespace: KRB
:Imports: :doc:`base/protocols/krb/consts.bro </scripts/base/protocols/krb/consts.bro>`

Summary
~~~~~~~
Runtime Options
###############
================================================================= =======================================================
:bro:id:`KRB::ignored_errors`: :bro:type:`set` :bro:attr:`&redef` The server response error texts which are *not* logged.
================================================================= =======================================================

Types
#####
========================================= =
:bro:type:`KRB::Info`: :bro:type:`record` 
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
========================================= ===================================================================
:bro:id:`KRB::log_krb`: :bro:type:`event` Event that can be handled to access the KRB record as it is sent on
                                          to the logging framework.
========================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: KRB::ignored_errors

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ",
         "NEEDED_PREAUTH"
      }

   The server response error texts which are *not* logged.

Types
#####
.. bro:type:: KRB::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the event happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      request_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Request type - Authentication Service ("AS") or
         Ticket Granting Service ("TGS")

      client: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Client

      service: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Service

      success: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Request result

      error_code: :bro:type:`count` :bro:attr:`&optional`
         Error code

      error_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Error message

      from: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         Ticket valid from

      till: :bro:type:`time` :bro:attr:`&log` :bro:attr:`&optional`
         Ticket valid till

      cipher: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Ticket encryption type

      forwardable: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Forwardable ticket requested

      renewable: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&optional`
         Renewable ticket requested

      logged: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         We've already logged this

      client_cert: :bro:type:`Files::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.bro` is loaded)

         Client certificate

      client_cert_subject: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.bro` is loaded)

         Subject of client certificate, if any

      client_cert_fuid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.bro` is loaded)

         File unique ID of client cert, if any

      server_cert: :bro:type:`Files::Info` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.bro` is loaded)

         Server certificate

      server_cert_subject: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.bro` is loaded)

         Subject of server certificate, if any

      server_cert_fuid: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/krb/files.bro` is loaded)

         File unique ID of server cert, if any

      auth_ticket: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/krb/ticket-logging.bro` is loaded)

         Hash of ticket used to authorize request/transaction

      new_ticket: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/krb/ticket-logging.bro` is loaded)

         Hash of ticket returned by the KDC


Events
######
.. bro:id:: KRB::log_krb

   :Type: :bro:type:`event` (rec: :bro:type:`KRB::Info`)

   Event that can be handled to access the KRB record as it is sent on
   to the logging framework.


