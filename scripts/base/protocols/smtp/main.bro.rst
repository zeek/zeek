:tocdepth: 3

base/protocols/smtp/main.bro
============================
.. bro:namespace:: SMTP


:Namespace: SMTP
:Imports: :doc:`base/utils/addrs.bro </scripts/base/utils/addrs.bro>`, :doc:`base/utils/directions-and-hosts.bro </scripts/base/utils/directions-and-hosts.bro>`, :doc:`base/utils/email.bro </scripts/base/utils/email.bro>`

Summary
~~~~~~~
Runtime Options
###############
====================================================================== ===================================================
:bro:id:`SMTP::mail_path_capture`: :bro:type:`Host` :bro:attr:`&redef` Direction to capture the full "Received from" path.
====================================================================== ===================================================

Types
#####
=========================================== =
:bro:type:`SMTP::Info`: :bro:type:`record`  
:bro:type:`SMTP::State`: :bro:type:`record` 
=========================================== =

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
=========================================== =
:bro:id:`SMTP::log_smtp`: :bro:type:`event` 
=========================================== =

Functions
#########
============================================== ===========================================================
:bro:id:`SMTP::describe`: :bro:type:`function` Create an extremely shortened representation of a log line.
============================================== ===========================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SMTP::mail_path_capture

   :Type: :bro:type:`Host`
   :Attributes: :bro:attr:`&redef`
   :Default: ``ALL_HOSTS``

   Direction to capture the full "Received from" path.
      REMOTE_HOSTS - only capture the path until an internal host is found.
      LOCAL_HOSTS - only capture the path until the external host is discovered.
      ALL_HOSTS - always capture the entire path.
      NO_HOSTS - never capture the path.

Types
#####
.. bro:type:: SMTP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Time when the message was first seen.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      trans_depth: :bro:type:`count` :bro:attr:`&log`
         A count to represent the depth of this message transaction in
         a single connection where multiple messages were transferred.

      helo: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Helo header.

      mailfrom: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Email addresses found in the From header.

      rcptto: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&optional`
         Email addresses found in the Rcpt header.

      date: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Date header.

      from: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the From header.

      to: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the To header.

      cc: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the CC header.

      reply_to: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the ReplyTo header.

      msg_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the MsgID header.

      in_reply_to: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the In-Reply-To header.

      subject: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Subject header.

      x_originating_ip: :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the X-Originating-IP header.

      first_received: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the first Received header.

      second_received: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the second Received header.

      last_reply: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The last message that the server sent to the client.

      path: :bro:type:`vector` of :bro:type:`addr` :bro:attr:`&log` :bro:attr:`&optional`
         The message transmission path, as extracted from the headers.

      user_agent: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value of the User-Agent header from the client.

      tls: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Indicates that the connection has switched to using TLS.

      process_received_from: :bro:type:`bool` :bro:attr:`&default` = ``T`` :bro:attr:`&optional`
         Indicates if the "Received: from" headers should still be
         processed.

      has_client_activity: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Indicates if client activity has been seen, but not yet logged.

      entity: :bro:type:`SMTP::Entity` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/entities.bro` is loaded)

         The current entity being seen.

      fuids: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&default` = ``[]`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/files.bro` is loaded)

         An ordered vector of file unique IDs seen attached to
         the message.

      is_webmail: :bro:type:`bool` :bro:attr:`&log` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/smtp/software.bro` is loaded)

         Boolean indicator of if the message was sent through a
         webmail interface.


.. bro:type:: SMTP::State

   :Type: :bro:type:`record`

      helo: :bro:type:`string` :bro:attr:`&optional`

      messages_transferred: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Count the number of individual messages transmitted during
         this SMTP session.  Note, this is not the number of
         recipients, but the number of message bodies transferred.

      pending_messages: :bro:type:`set` [:bro:type:`SMTP::Info`] :bro:attr:`&optional`

      mime_depth: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/smtp/entities.bro` is loaded)

         Track the number of MIME encoded files transferred
         during a session.


Events
######
.. bro:id:: SMTP::log_smtp

   :Type: :bro:type:`event` (rec: :bro:type:`SMTP::Info`)


Functions
#########
.. bro:id:: SMTP::describe

   :Type: :bro:type:`function` (rec: :bro:type:`SMTP::Info`) : :bro:type:`string`

   Create an extremely shortened representation of a log line.


