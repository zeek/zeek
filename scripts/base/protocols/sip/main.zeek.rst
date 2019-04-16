:tocdepth: 3

base/protocols/sip/main.zeek
============================
.. bro:namespace:: SIP

Implements base functionality for SIP analysis.  The logging model is
to log request/response pairs and all relevant metadata together in
a single record.

:Namespace: SIP
:Imports: :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================== ======================
:bro:id:`SIP::sip_methods`: :bro:type:`set` :bro:attr:`&redef` A list of SIP methods.
============================================================== ======================

Types
#####
========================================== =========================================================
:bro:type:`SIP::Info`: :bro:type:`record`  The record type which contains the fields of the SIP log.
:bro:type:`SIP::State`: :bro:type:`record` 
========================================== =========================================================

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
:bro:id:`SIP::log_sip`: :bro:type:`event` Event that can be handled to access the SIP record as it is sent on
                                          to the logging framework.
========================================= ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: SIP::sip_methods

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "NOTIFY",
         "ACK",
         "SUBSCRIBE",
         "CANCEL",
         "OPTIONS",
         "REGISTER",
         "INVITE",
         "BYE"
      }

   A list of SIP methods. Other methods will generate a weird. Note
   that the SIP analyzer will only accept methods consisting solely
   of letters ``[A-Za-z]``.

Types
#####
.. bro:type:: SIP::Info

   :Type: :bro:type:`record`

      ts: :bro:type:`time` :bro:attr:`&log`
         Timestamp for when the request happened.

      uid: :bro:type:`string` :bro:attr:`&log`
         Unique ID for the connection.

      id: :bro:type:`conn_id` :bro:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      trans_depth: :bro:type:`count` :bro:attr:`&log`
         Represents the pipelined depth into the connection of this
         request/response transaction.

      method: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Verb used in the SIP request (INVITE, REGISTER etc.).

      uri: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         URI used in the request.

      date: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Date: header from the client

      request_from: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the request From: header
         Note: The tag= value that's usually appended to the sender
         is stripped off and not logged.

      request_to: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the To: header

      response_from: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the response From: header
         Note: The ``tag=`` value that's usually appended to the sender
         is stripped off and not logged.

      response_to: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the response To: header

      reply_to: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Reply-To: header

      call_id: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Call-ID: header from the client

      seq: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the CSeq: header from the client

      subject: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Subject: header from the client

      request_path: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The client message transmission path, as extracted from the headers.

      response_path: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         The server message transmission path, as extracted from the headers.

      user_agent: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the User-Agent: header from the client

      status_code: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Status code returned by the server.

      status_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Status message returned by the server.

      warning: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Warning: header

      request_body_len: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Content-Length: header from the client

      response_body_len: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Content-Length: header from the server

      content_type: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Contents of the Content-Type: header from the server

   The record type which contains the fields of the SIP log.

.. bro:type:: SIP::State

   :Type: :bro:type:`record`

      pending: :bro:type:`table` [:bro:type:`count`] of :bro:type:`SIP::Info`
         Pending requests.

      current_request: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Current request in the pending queue.

      current_response: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Current response in the pending queue.


Events
######
.. bro:id:: SIP::log_sip

   :Type: :bro:type:`event` (rec: :bro:type:`SIP::Info`)

   Event that can be handled to access the SIP record as it is sent on
   to the logging framework.


