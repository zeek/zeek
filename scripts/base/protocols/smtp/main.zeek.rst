:tocdepth: 3

base/protocols/smtp/main.zeek
=============================
.. zeek:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/utils/addrs.zeek </scripts/base/utils/addrs.zeek>`, :doc:`base/utils/directions-and-hosts.zeek </scripts/base/utils/directions-and-hosts.zeek>`, :doc:`base/utils/email.zeek </scripts/base/utils/email.zeek>`

Summary
~~~~~~~
Runtime Options
###############
========================================================================= ===================================================
:zeek:id:`SMTP::mail_path_capture`: :zeek:type:`Host` :zeek:attr:`&redef` Direction to capture the full "Received from" path.
========================================================================= ===================================================

Types
#####
============================================= =
:zeek:type:`SMTP::Info`: :zeek:type:`record`  
:zeek:type:`SMTP::State`: :zeek:type:`record` 
============================================= =

Redefinitions
#############
==================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =

Events
######
============================================= =
:zeek:id:`SMTP::log_smtp`: :zeek:type:`event` 
============================================= =

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

   :Type: :zeek:type:`Host`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``ALL_HOSTS``

   Direction to capture the full "Received from" path.
      REMOTE_HOSTS - only capture the path until an internal host is found.
      LOCAL_HOSTS - only capture the path until the external host is discovered.
      ALL_HOSTS - always capture the entire path.
      NO_HOSTS - never capture the path.

Types
#####
.. zeek:type:: SMTP::Info

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

   :Type: :zeek:type:`record`

      helo: :zeek:type:`string` :zeek:attr:`&optional`

      messages_transferred: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Count the number of individual messages transmitted during
         this SMTP session.  Note, this is not the number of
         recipients, but the number of message bodies transferred.

      pending_messages: :zeek:type:`set` [:zeek:type:`SMTP::Info`] :zeek:attr:`&optional`

      mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/entities.zeek` is loaded)

         Track the number of MIME encoded files transferred
         during a session.


Events
######
.. zeek:id:: SMTP::log_smtp

   :Type: :zeek:type:`event` (rec: :zeek:type:`SMTP::Info`)


Functions
#########
.. zeek:id:: SMTP::describe

   :Type: :zeek:type:`function` (rec: :zeek:type:`SMTP::Info`) : :zeek:type:`string`

   Create an extremely shortened representation of a log line.


