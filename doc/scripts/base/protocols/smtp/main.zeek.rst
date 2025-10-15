:tocdepth: 3

base/protocols/smtp/main.zeek
=============================
.. zeek:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`base/utils/email.zeek </scripts/base/utils/email.zeek>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================================== ================================================================
:zeek:id:`SMTP::mail_path_capture`: :zeek:type:`Host` :zeek:attr:`&redef`              Direction to capture the full "Received from" path.
:zeek:id:`SMTP::mail_transaction_validation`: :zeek:type:`bool` :zeek:attr:`&redef`    When seeing a RCPT TO or DATA command, validate that it has been
                                                                                       preceded by a MAIL FROM or RCPT TO command, respectively, else
                                                                                       log a weird and possibly disable the SMTP analyzer upon too
                                                                                       many invalid transactions.
:zeek:id:`SMTP::max_invalid_mail_transactions`: :zeek:type:`count` :zeek:attr:`&redef` Disable the SMTP analyzer when that many invalid transactions
                                                                                       have been observed in an SMTP session.
====================================================================================== ================================================================

Types
#####
============================================= =
:zeek:type:`SMTP::Info`: :zeek:type:`record`  
:zeek:type:`SMTP::State`: :zeek:type:`record` 
============================================= =

Redefinitions
#############
==================================================================== =============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
                                                                     
                                                                     * :zeek:enum:`SMTP::LOG`
:zeek:type:`connection`: :zeek:type:`record`                         
                                                                     
                                                                     :New Fields: :zeek:type:`connection`
                                                                     
                                                                       smtp: :zeek:type:`SMTP::Info` :zeek:attr:`&optional`
                                                                     
                                                                       smtp_state: :zeek:type:`SMTP::State` :zeek:attr:`&optional`
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =============================================================

Events
######
============================================= =
:zeek:id:`SMTP::log_smtp`: :zeek:type:`event` 
============================================= =

Hooks
#####
============================================================== =======================
:zeek:id:`SMTP::finalize_smtp`: :zeek:type:`Conn::RemovalHook` SMTP finalization hook.
:zeek:id:`SMTP::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =======================

Functions
#########
================================================ ===========================================================
:zeek:id:`SMTP::describe`: :zeek:type:`function` Create an extremely shortened representation of a log line.
================================================ ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SMTP::mail_path_capture
   :source-code: base/protocols/smtp/main.zeek 92 92

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``ALL_HOSTS``

   Direction to capture the full "Received from" path.
      REMOTE_HOSTS - only capture the path until an internal host is found.
      LOCAL_HOSTS - only capture the path until the external host is discovered.
      ALL_HOSTS - always capture the entire path.
      NO_HOSTS - never capture the path.

.. zeek:id:: SMTP::mail_transaction_validation
   :source-code: base/protocols/smtp/main.zeek 106 106

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   When seeing a RCPT TO or DATA command, validate that it has been
   preceded by a MAIL FROM or RCPT TO command, respectively, else
   log a weird and possibly disable the SMTP analyzer upon too
   many invalid transactions.

.. zeek:id:: SMTP::max_invalid_mail_transactions
   :source-code: base/protocols/smtp/main.zeek 110 110

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``25``

   Disable the SMTP analyzer when that many invalid transactions
   have been observed in an SMTP session.

Types
#####
.. zeek:type:: SMTP::Info
   :source-code: base/protocols/smtp/main.zeek 14 69

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Time when the message was first seen.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      trans_depth: :zeek:type:`count` :zeek:attr:`&log`
         A count to represent the depth of this message transaction in
         a single connection where multiple messages were transferred.

      helo: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Helo header.

      mailfrom: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Email addresses found in the From header.

      rcptto: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`
         Email addresses found in the Rcpt header.

      date: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Date header.

      from: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the From header.

      to: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the To header.

      cc: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the CC header.

      reply_to: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the ReplyTo header.

      msg_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the MsgID header.

      in_reply_to: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the In-Reply-To header.

      subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Subject header.

      x_originating_ip: :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the X-Originating-IP header.

      first_received: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the first Received header.

      second_received: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the second Received header.

      last_reply: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The last message that the server sent to the client.

      path: :zeek:type:`vector` of :zeek:type:`addr` :zeek:attr:`&log` :zeek:attr:`&optional`
         The message transmission path, as extracted from the headers.

      user_agent: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value of the User-Agent header from the client.

      tls: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicates that the connection has switched to using TLS.

      process_received_from: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Indicates if the "Received: from" headers should still be
         processed.

      has_client_activity: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicates if client activity has been seen, but not yet logged.

      process_smtp_headers: :zeek:type:`bool` :zeek:attr:`&default` = ``T`` :zeek:attr:`&optional`
         Indicates if the SMTP headers should still be processed.

      entity_count: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      entity: :zeek:type:`SMTP::Entity` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/entities.zeek` is loaded)

         The current entity being seen.

      fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&default` = ``[]`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/files.zeek` is loaded)

         An ordered vector of file unique IDs seen attached to
         the message.

      is_webmail: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/smtp/software.zeek` is loaded)

         Boolean indicator of if the message was sent through a
         webmail interface.


.. zeek:type:: SMTP::State
   :source-code: base/protocols/smtp/main.zeek 71 85

   :Type: :zeek:type:`record`

      helo: :zeek:type:`string` :zeek:attr:`&optional`

      messages_transferred: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Count the number of individual messages transmitted during
         this SMTP session.  Note, this is not the number of
         recipients, but the number of message bodies transferred.

      pending_messages: :zeek:type:`set` [:zeek:type:`SMTP::Info`] :zeek:attr:`&optional`

      trans_mail_from_seen: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      trans_rcpt_to_seen: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      invalid_transactions: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      bdat_last_observed: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      analyzer_id: :zeek:type:`count` :zeek:attr:`&optional`

      mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/entities.zeek` is loaded)

         Track the number of MIME encoded files transferred
         during a session.


Events
######
.. zeek:id:: SMTP::log_smtp
   :source-code: base/protocols/smtp/main.zeek 97 97

   :Type: :zeek:type:`event` (rec: :zeek:type:`SMTP::Info`)


Hooks
#####
.. zeek:id:: SMTP::finalize_smtp
   :source-code: base/protocols/smtp/main.zeek 401 405

   :Type: :zeek:type:`Conn::RemovalHook`

   SMTP finalization hook.  Remaining SMTP info may get logged when it's called.

.. zeek:id:: SMTP::log_policy
   :source-code: base/protocols/smtp/main.zeek 12 12

   :Type: :zeek:type:`Log::PolicyHook`


Functions
#########
.. zeek:id:: SMTP::describe
   :source-code: base/protocols/smtp/main.zeek 416 441

   :Type: :zeek:type:`function` (rec: :zeek:type:`SMTP::Info`) : :zeek:type:`string`

   Create an extremely shortened representation of a log line.


