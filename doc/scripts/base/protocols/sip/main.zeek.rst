:tocdepth: 3

base/protocols/sip/main.zeek
============================
.. zeek:namespace:: SIP

Implements base functionality for SIP analysis.  The logging model is
to log request/response pairs and all relevant metadata together in
a single record.

:Namespace: SIP
:Imports: :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================= ======================
:zeek:id:`SIP::sip_methods`: :zeek:type:`set` :zeek:attr:`&redef` A list of SIP methods.
================================================================= ======================

Redefinable Options
###################
=========================================================== =========================
:zeek:id:`SIP::ports`: :zeek:type:`set` :zeek:attr:`&redef` Well-known ports for SIP.
=========================================================== =========================

Types
#####
============================================ =========================================================
:zeek:type:`SIP::Info`: :zeek:type:`record`  The record type which contains the fields of the SIP log.
:zeek:type:`SIP::State`: :zeek:type:`record`
============================================ =========================================================

Redefinitions
#############
============================================ ===========================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`

                                             * :zeek:enum:`SIP::LOG`
:zeek:type:`connection`: :zeek:type:`record`

                                             :New Fields: :zeek:type:`connection`

                                               sip: :zeek:type:`SIP::Info` :zeek:attr:`&optional`

                                               sip_state: :zeek:type:`SIP::State` :zeek:attr:`&optional`
============================================ ===========================================================

Events
######
=========================================== ===================================================================
:zeek:id:`SIP::log_sip`: :zeek:type:`event` Event that can be handled to access the SIP record as it is sent on
                                            to the logging framework.
=========================================== ===================================================================

Hooks
#####
============================================================ ======================
:zeek:id:`SIP::finalize_sip`: :zeek:type:`Conn::RemovalHook` SIP finalization hook.
:zeek:id:`SIP::log_policy`: :zeek:type:`Log::PolicyHook`
============================================================ ======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: SIP::sip_methods
   :source-code: base/protocols/sip/main.zeek 89 89

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "BYE",
            "SUBSCRIBE",
            "NOTIFY",
            "REGISTER",
            "INVITE",
            "CANCEL",
            "OPTIONS",
            "ACK"
         }


   A list of SIP methods. Other methods will generate a weird. Note
   that the SIP analyzer will only accept methods consisting solely
   of letters ``[A-Za-z]``.

Redefinable Options
###################
.. zeek:id:: SIP::ports
   :source-code: base/protocols/sip/main.zeek 15 15

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            5060/udp
         }


   Well-known ports for SIP.

Types
#####
.. zeek:type:: SIP::Info
   :source-code: base/protocols/sip/main.zeek 20 75

   :Type: :zeek:type:`record`


   .. zeek:field:: ts :zeek:type:`time` :zeek:attr:`&log`

      Timestamp for when the request happened.


   .. zeek:field:: uid :zeek:type:`string` :zeek:attr:`&log`

      Unique ID for the connection.


   .. zeek:field:: id :zeek:type:`conn_id` :zeek:attr:`&log`

      The connection's 4-tuple of endpoint addresses/ports.


   .. zeek:field:: trans_depth :zeek:type:`count` :zeek:attr:`&log`

      Represents the pipelined depth into the connection of this
      request/response transaction.


   .. zeek:field:: method :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Verb used in the SIP request (INVITE, REGISTER etc.).


   .. zeek:field:: uri :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      URI used in the request.


   .. zeek:field:: date :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Date: header from the client


   .. zeek:field:: request_from :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the request From: header
      Note: The tag= value that's usually appended to the sender
      is stripped off and not logged.


   .. zeek:field:: request_to :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the To: header


   .. zeek:field:: response_from :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the response From: header
      Note: The ``tag=`` value that's usually appended to the sender
      is stripped off and not logged.


   .. zeek:field:: response_to :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the response To: header


   .. zeek:field:: reply_to :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Reply-To: header


   .. zeek:field:: call_id :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Call-ID: header from the client


   .. zeek:field:: seq :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the CSeq: header from the client


   .. zeek:field:: subject :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Subject: header from the client


   .. zeek:field:: request_path :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The client message transmission path, as extracted from the headers.


   .. zeek:field:: response_path :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      The server message transmission path, as extracted from the headers.


   .. zeek:field:: user_agent :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the User-Agent: header from the client


   .. zeek:field:: status_code :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status code returned by the server.


   .. zeek:field:: status_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status message returned by the server.


   .. zeek:field:: warning :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Warning: header


   .. zeek:field:: request_body_len :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Content-Length: header from the client


   .. zeek:field:: response_body_len :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Content-Length: header from the server


   .. zeek:field:: content_type :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Contents of the Content-Type: header from the server


   The record type which contains the fields of the SIP log.

.. zeek:type:: SIP::State
   :source-code: base/protocols/sip/main.zeek 77 84

   :Type: :zeek:type:`record`


   .. zeek:field:: pending :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`SIP::Info`

      Pending requests.


   .. zeek:field:: current_request :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Current request in the pending queue.


   .. zeek:field:: current_response :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Current response in the pending queue.



Events
######
.. zeek:id:: SIP::log_sip
   :source-code: base/protocols/sip/main.zeek 95 95

   :Type: :zeek:type:`event` (rec: :zeek:type:`SIP::Info`)

   Event that can be handled to access the SIP record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: SIP::finalize_sip
   :source-code: base/protocols/sip/main.zeek 300 309

   :Type: :zeek:type:`Conn::RemovalHook`

   SIP finalization hook.  Remaining SIP info may get logged when it's called.

.. zeek:id:: SIP::log_policy
   :source-code: base/protocols/sip/main.zeek 17 17

   :Type: :zeek:type:`Log::PolicyHook`



