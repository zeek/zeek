:tocdepth: 3

base/protocols/sip/main.zeek
============================
.. zeek:namespace:: SIP

Implements base functionality for SIP analysis.  The logging model is
to log request/response pairs and all relevant metadata together in
a single record.

:Namespace: SIP
:Imports: :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================= ======================
:zeek:id:`SIP::sip_methods`: :zeek:type:`set` :zeek:attr:`&redef` A list of SIP methods.
================================================================= ======================

Types
#####
============================================ =========================================================
:zeek:type:`SIP::Info`: :zeek:type:`record`  The record type which contains the fields of the SIP log.
:zeek:type:`SIP::State`: :zeek:type:`record` 
============================================ =========================================================

Redefinitions
#############
==================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =

Events
######
=========================================== ===================================================================
:zeek:id:`SIP::log_sip`: :zeek:type:`event` Event that can be handled to access the SIP record as it is sent on
                                            to the logging framework.
=========================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SIP::sip_methods

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
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
.. zeek:type:: SIP::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         Timestamp for when the request happened.

      uid: :zeek:type:`string` :zeek:attr:`&log`
         Unique ID for the connection.

      id: :zeek:type:`conn_id` :zeek:attr:`&log`
         The connection's 4-tuple of endpoint addresses/ports.

      trans_depth: :zeek:type:`count` :zeek:attr:`&log`
         Represents the pipelined depth into the connection of this
         request/response transaction.

      method: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Verb used in the SIP request (INVITE, REGISTER etc.).

      uri: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         URI used in the request.

      date: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Date: header from the client

      request_from: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the request From: header
         Note: The tag= value that's usually appended to the sender
         is stripped off and not logged.

      request_to: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the To: header

      response_from: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the response From: header
         Note: The ``tag=`` value that's usually appended to the sender
         is stripped off and not logged.

      response_to: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the response To: header

      reply_to: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Reply-To: header

      call_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Call-ID: header from the client

      seq: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the CSeq: header from the client

      subject: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Subject: header from the client

      request_path: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The client message transmission path, as extracted from the headers.

      response_path: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         The server message transmission path, as extracted from the headers.

      user_agent: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the User-Agent: header from the client

      status_code: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Status code returned by the server.

      status_msg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Status message returned by the server.

      warning: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Warning: header

      request_body_len: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Content-Length: header from the client

      response_body_len: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Content-Length: header from the server

      content_type: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Contents of the Content-Type: header from the server

   The record type which contains the fields of the SIP log.

.. zeek:type:: SIP::State

   :Type: :zeek:type:`record`

      pending: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`SIP::Info`
         Pending requests.

      current_request: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Current request in the pending queue.

      current_response: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Current response in the pending queue.


Events
######
.. zeek:id:: SIP::log_sip

   :Type: :zeek:type:`event` (rec: :zeek:type:`SIP::Info`)

   Event that can be handled to access the SIP record as it is sent on
   to the logging framework.


