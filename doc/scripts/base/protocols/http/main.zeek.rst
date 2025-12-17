:tocdepth: 3

base/protocols/http/main.zeek
=============================
.. zeek:namespace:: HTTP

Implements base functionality for HTTP analysis.  The logging model is
to log request/response pairs and all relevant metadata together in
a single record.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/tunnels </scripts/base/frameworks/tunnels/index>`, :doc:`base/protocols/conn/removal-hooks.zeek </scripts/base/protocols/conn/removal-hooks.zeek>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================ ====================================================================
:zeek:id:`HTTP::default_capture_password`: :zeek:type:`bool` :zeek:attr:`&redef` This setting changes if passwords used in Basic-Auth are captured or
                                                                                 not.
:zeek:id:`HTTP::http_methods`: :zeek:type:`set` :zeek:attr:`&redef`              A list of HTTP methods.
:zeek:id:`HTTP::max_pending_requests`: :zeek:type:`count` :zeek:attr:`&redef`    Only allow that many pending requests on a single connection.
:zeek:id:`HTTP::proxy_headers`: :zeek:type:`set` :zeek:attr:`&redef`             A list of HTTP headers typically used to indicate proxied requests.
================================================================================ ====================================================================

Redefinable Options
###################
======================================================================================= =======================================================================
:zeek:id:`HTTP::default_max_field_string_bytes`: :zeek:type:`count` :zeek:attr:`&redef` The maximum number of bytes that a single string field can contain when
                                                                                        logging.
:zeek:id:`HTTP::ports`: :zeek:type:`set` :zeek:attr:`&redef`                            Well-known ports for HTTP.
======================================================================================= =======================================================================

Types
#####
============================================= ===================================================================
:zeek:type:`HTTP::Info`: :zeek:type:`record`  The record type which contains the fields of the HTTP log.
:zeek:type:`HTTP::State`: :zeek:type:`record` Structure to maintain state for an HTTP connection with multiple
                                              requests and responses.
:zeek:type:`HTTP::Tags`: :zeek:type:`enum`    Indicate a type of attack or compromise in the record to be logged.
============================================= ===================================================================

Redefinitions
#############
============================================ =============================================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      
                                             
                                             * :zeek:enum:`HTTP::LOG`
:zeek:type:`connection`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`connection`
                                             
                                               http: :zeek:type:`HTTP::Info` :zeek:attr:`&optional`
                                             
                                               http_state: :zeek:type:`HTTP::State` :zeek:attr:`&optional`
============================================ =============================================================

Events
######
============================================= ====================================================================
:zeek:id:`HTTP::log_http`: :zeek:type:`event` Event that can be handled to access the HTTP record as it is sent on
                                              to the logging framework.
============================================= ====================================================================

Hooks
#####
============================================================== =======================
:zeek:id:`HTTP::finalize_http`: :zeek:type:`Conn::RemovalHook` HTTP finalization hook.
:zeek:id:`HTTP::log_policy`: :zeek:type:`Log::PolicyHook`      
============================================================== =======================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: HTTP::default_capture_password
   :source-code: base/protocols/http/main.zeek 31 31

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   This setting changes if passwords used in Basic-Auth are captured or
   not.

.. zeek:id:: HTTP::http_methods
   :source-code: base/protocols/http/main.zeek 126 126

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "POST",
            "PUT",
            "CONNECT",
            "BMOVE",
            "SEARCH",
            "TRACE",
            "LOCK",
            "PROPPATCH",
            "HEAD",
            "OPTIONS",
            "POLL",
            "REPORT",
            "SUBSCRIBE",
            "MOVE",
            "GET",
            "UNLOCK",
            "DELETE",
            "COPY",
            "MKCOL",
            "PROPFIND"
         }


   A list of HTTP methods. Other methods will generate a weird. Note
   that the HTTP analyzer will only accept methods consisting solely
   of letters ``[A-Za-z]``.

.. zeek:id:: HTTP::max_pending_requests
   :source-code: base/protocols/http/main.zeek 147 147

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``100``

   Only allow that many pending requests on a single connection.
   If this number is exceeded, all pending requests are flushed
   out and request/response tracking reset to prevent unbounded
   state growth.

.. zeek:id:: HTTP::proxy_headers
   :source-code: base/protocols/http/main.zeek 113 113

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "CLIENT-IP",
            "X-FORWARDED-FROM",
            "VIA",
            "XROXY-CONNECTION",
            "PROXY-CONNECTION",
            "X-FORWARDED-FOR",
            "FORWARDED"
         }


   A list of HTTP headers typically used to indicate proxied requests.

Redefinable Options
###################
.. zeek:id:: HTTP::default_max_field_string_bytes
   :source-code: base/protocols/http/main.zeek 155 155

   :Type: :zeek:type:`count`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``0``

   The maximum number of bytes that a single string field can contain when
   logging. If a string reaches this limit, the log output for the field will be
   truncated. Setting this to zero disables the limiting. HTTP has no maximum
   length for various fields such as the URI, so this is set to zero by default.
   
   .. zeek:see:: Log::default_max_field_string_bytes

.. zeek:id:: HTTP::ports
   :source-code: base/protocols/http/main.zeek 16 16

   :Type: :zeek:type:`set` [:zeek:type:`port`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            80/tcp,
            8888/tcp,
            81/tcp,
            8000/tcp,
            3128/tcp,
            8080/tcp,
            631/tcp,
            1080/tcp
         }


   Well-known ports for HTTP.

Types
#####
.. zeek:type:: HTTP::Info
   :source-code: base/protocols/http/main.zeek 34 95

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

      Verb used in the HTTP request (GET, POST, HEAD, etc.).


   .. zeek:field:: host :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value of the HOST header.


   .. zeek:field:: uri :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      URI used in the request.


   .. zeek:field:: referrer :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value of the "referer" header.  The comment is deliberately
      misspelled like the standard declares, but the name used here
      is "referrer", spelled correctly.


   .. zeek:field:: version :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value of the version portion of the reply. If you require
      message-level detail, consider the :zeek:see:`http_request` and
      :zeek:see:`http_reply` events, which report each message's
      version string.


   .. zeek:field:: user_agent :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value of the User-Agent header from the client.


   .. zeek:field:: origin :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Value of the Origin header from the client.


   .. zeek:field:: request_body_len :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Actual uncompressed content size of the data transferred from
      the client.


   .. zeek:field:: response_body_len :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Actual uncompressed content size of the data transferred from
      the server.


   .. zeek:field:: status_code :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status code returned by the server.


   .. zeek:field:: status_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Status message returned by the server.


   .. zeek:field:: info_code :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`

      Last seen 1xx informational reply code returned by the server.


   .. zeek:field:: info_msg :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Last seen 1xx informational reply message returned by the server.


   .. zeek:field:: tags :zeek:type:`set` [:zeek:type:`HTTP::Tags`] :zeek:attr:`&log`

      A set of indicators of various attributes discovered and
      related to a particular request/response pair.


   .. zeek:field:: username :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Username if basic-auth is performed for the request.


   .. zeek:field:: password :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      Password if basic-auth is performed for the request.


   .. zeek:field:: capture_password :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`HTTP::default_capture_password` :zeek:attr:`&optional`

      Determines if the password will be captured for this request.


   .. zeek:field:: proxied :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`

      All of the headers that may indicate if the request was proxied.


   .. zeek:field:: range_request :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      Indicates if this request can assume 206 partial content in
      response.


   .. zeek:field:: orig_fuids :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      An ordered vector of file unique IDs.
      Limited to :zeek:see:`HTTP::max_files_orig` entries.


   .. zeek:field:: orig_filenames :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      An ordered vector of filenames from the client.
      Limited to :zeek:see:`HTTP::max_files_orig` entries.


   .. zeek:field:: orig_mime_types :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      An ordered vector of mime types.
      Limited to :zeek:see:`HTTP::max_files_orig` entries.


   .. zeek:field:: resp_fuids :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      An ordered vector of file unique IDs.
      Limited to :zeek:see:`HTTP::max_files_resp` entries.


   .. zeek:field:: resp_filenames :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      An ordered vector of filenames from the server.
      Limited to :zeek:see:`HTTP::max_files_resp` entries.


   .. zeek:field:: resp_mime_types :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      An ordered vector of mime types.
      Limited to :zeek:see:`HTTP::max_files_resp` entries.


   .. zeek:field:: current_entity :zeek:type:`HTTP::Entity` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      The current entity.


   .. zeek:field:: orig_mime_depth :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      Current number of MIME entities in the HTTP request message
      body.


   .. zeek:field:: resp_mime_depth :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

      Current number of MIME entities in the HTTP response message
      body.


   .. zeek:field:: client_header_names :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/http/header-names.zeek` is loaded)

      The vector of HTTP header names sent by the client.  No
      header values are included here, just the header names.


   .. zeek:field:: server_header_names :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/http/header-names.zeek` is loaded)

      The vector of HTTP header names sent by the server.  No
      header values are included here, just the header names.


   .. zeek:field:: omniture :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.zeek` is loaded)

      Indicates if the server is an omniture advertising server.


   .. zeek:field:: flash_version :zeek:type:`string` :zeek:attr:`&optional`

      (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.zeek` is loaded)

      The unparsed Flash version, if detected.


   .. zeek:field:: cookie_vars :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/protocols/http/var-extraction-cookies.zeek` is loaded)

      Variable names extracted from all cookies.


   .. zeek:field:: uri_vars :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`

      (present if :doc:`/scripts/policy/protocols/http/var-extraction-uri.zeek` is loaded)

      Variable names from the URI.


   The record type which contains the fields of the HTTP log.

.. zeek:type:: HTTP::State
   :source-code: base/protocols/http/main.zeek 99 110

   :Type: :zeek:type:`record`


   .. zeek:field:: pending :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`HTTP::Info`

      Pending requests.


   .. zeek:field:: current_request :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Current request in the pending queue.


   .. zeek:field:: current_response :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Current response in the pending queue.


   .. zeek:field:: trans_depth :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`

      Track the current deepest transaction.
      This is meant to cope with missing requests
      and responses.


   Structure to maintain state for an HTTP connection with multiple
   requests and responses.

.. zeek:type:: HTTP::Tags
   :source-code: base/protocols/http/main.zeek 24 28

   :Type: :zeek:type:`enum`

      .. zeek:enum:: HTTP::EMPTY HTTP::Tags

         Placeholder.

      .. zeek:enum:: HTTP::URI_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sql-injection.zeek` is loaded)


         Indicator of a URI based SQL injection attack.

   Indicate a type of attack or compromise in the record to be logged.

Events
######
.. zeek:id:: HTTP::log_http
   :source-code: base/protocols/http/main.zeek 138 138

   :Type: :zeek:type:`event` (rec: :zeek:type:`HTTP::Info`)

   Event that can be handled to access the HTTP record as it is sent on
   to the logging framework.

Hooks
#####
.. zeek:id:: HTTP::finalize_http
   :source-code: base/protocols/http/main.zeek 394 406

   :Type: :zeek:type:`Conn::RemovalHook`

   HTTP finalization hook.  Remaining HTTP info may get logged when it's called.

.. zeek:id:: HTTP::log_policy
   :source-code: base/protocols/http/main.zeek 21 21

   :Type: :zeek:type:`Log::PolicyHook`



