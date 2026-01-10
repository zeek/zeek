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

Redefinable Options
###################
=============================================================== ==================================
:zeek:id:`KRB::tcp_ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for KRB over TCP.
:zeek:id:`KRB::udp_ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for KRB over UDP.
=============================================================== ==================================

Types
#####
=========================================== =
:zeek:type:`KRB::Info`: :zeek:type:`record`
=========================================== =

Redefinitions
#############
============================================ ====================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`KRB::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               krb: :zeek:type:`KRB::Info` :zeek:attr:`&optional`
============================================ ====================================================

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
   :source-code: base/protocols/krb/main.zeek 60 60

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "NEEDED_PREAUTH",
            "Need to use PA-ENC-TIMESTAMP/PA-PK-AS-REQ"
         }


   The server response error texts which are *not* logged.

Redefinable Options
###################
.. zeek:id:: KRB::tcp_ports
   :source-code: base/protocols/krb/main.zeek 13 13

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            88/tcp
         }


   Well-known ports for KRB over TCP.

.. zeek:id:: KRB::udp_ports
   :source-code: base/protocols/krb/main.zeek 16 16

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            88/udp
         }


   Well-known ports for KRB over UDP.

Types
#####
.. zeek:type:: KRB::Info
   :source-code: base/protocols/krb/main.zeek 20 57

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the event happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: request_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Request type - Authentication Service ("AS") or
      Ticket Granting Service ("TGS")


   .. zeek:field:: client :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Client


   .. zeek:field:: service :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Service


   .. zeek:field:: success :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Request result


   .. zeek:field:: error_code :zeek:type:`count` :zeek:attr:`&optional`

      Error code


   .. zeek:field:: error_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Error message


   .. zeek:field:: from :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      Ticket valid from


   .. zeek:field:: till :zeek:type:`time` :zeek:attr:`&log` :zeek:attr:`&optional`

      Ticket valid till


   .. zeek:field:: cipher :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Ticket encryption type


   .. zeek:field:: forwardable :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Forwardable ticket requested


   .. zeek:field:: renewable :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&optional`

      Renewable ticket requested


   .. zeek:field:: logged :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      We've already logged this


   .. zeek:field:: client_cert :zeek:type:`Files::Info` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

      Client certificate


   .. zeek:field:: client_cert_subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

      Subject of client certificate, if any


   .. zeek:field:: client_cert_fuid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

      File unique ID of client cert, if any


   .. zeek:field:: server_cert :zeek:type:`Files::Info` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

      Server certificate


   .. zeek:field:: server_cert_subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

      Subject of server certificate, if any


   .. zeek:field:: server_cert_fuid :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/krb/files.zeek` is loaded)

      File unique ID of server cert, if any


   .. zeek:field:: auth_ticket_sha256 :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/krb/ticket-logging.zeek` is loaded)

      SHA256 hash of ticket used to authorize request/transaction


   .. zeek:field:: new_ticket_sha256 :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/krb/ticket-logging.zeek` is loaded)

      SHA256 hash of ticket returned by the KDC


   .. zeek:field:: auth_ticket :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/krb/md5-ticket-logging.zeek` is loaded)

      MD5 hash of ticket used to authorize request/transaction


   .. zeek:field:: new_ticket :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/krb/md5-ticket-logging.zeek` is loaded)

      MD5 hash of ticket returned by the KDC



Events
######
.. zeek:id:: KRB::log_krb
   :source-code: base/protocols/krb/main.zeek 74 74

   :Type: :zeek:type:`event` (rec: :zeek:type:`KRB::Info`)

   Event that can be handled to access the KRB record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: KRB::finalize_krb
   :source-code: base/protocols/krb/main.zeek 77 77

   :Type: :zeek:type:`Conn::RemovalHook`

   Kerberos finalization hook.  Remaining Kerberos info may get logged when it's called.

.. zeek:id:: KRB::log_policy
   :source-code: base/protocols/krb/main.zeek 18 18

   :Type: :zeek:type:`Log::PolicyHook`



