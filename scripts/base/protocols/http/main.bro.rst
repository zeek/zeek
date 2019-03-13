:tocdepth: 3

base/protocols/http/main.bro
============================
.. bro:namespace:: HTTP

Implements base functionality for HTTP analysis.  The logging model is
to log request/response pairs and all relevant metadata together in
a single record.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/tunnels </scripts/base/frameworks/tunnels/index>`, :doc:`base/utils/files.bro </scripts/base/utils/files.bro>`, :doc:`base/utils/numbers.bro </scripts/base/utils/numbers.bro>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================= ====================================================================
:bro:id:`HTTP::default_capture_password`: :bro:type:`bool` :bro:attr:`&redef` This setting changes if passwords used in Basic-Auth are captured or
                                                                              not.
:bro:id:`HTTP::http_methods`: :bro:type:`set` :bro:attr:`&redef`              A list of HTTP methods.
:bro:id:`HTTP::proxy_headers`: :bro:type:`set` :bro:attr:`&redef`             A list of HTTP headers typically used to indicate proxied requests.
============================================================================= ====================================================================

Types
#####
=========================================== ===================================================================
:bro:type:`HTTP::Info`: :bro:type:`record`  The record type which contains the fields of the HTTP log.
:bro:type:`HTTP::State`: :bro:type:`record` Structure to maintain state for an HTTP connection with multiple
                                            requests and responses.
:bro:type:`HTTP::Tags`: :bro:type:`enum`    Indicate a type of attack or compromise in the record to be logged.
=========================================== ===================================================================

Redefinitions
#############
================================================================= =
:bro:type:`Log::ID`: :bro:type:`enum`                             
:bro:type:`connection`: :bro:type:`record`                        
:bro:id:`likely_server_ports`: :bro:type:`set` :bro:attr:`&redef` 
================================================================= =

Events
######
=========================================== ====================================================================
:bro:id:`HTTP::log_http`: :bro:type:`event` Event that can be handled to access the HTTP record as it is sent on
                                            to the logging framework.
=========================================== ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: HTTP::default_capture_password

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   This setting changes if passwords used in Basic-Auth are captured or
   not.

.. bro:id:: HTTP::http_methods

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "MKCOL",
         "MOVE",
         "LOCK",
         "SUBSCRIBE",
         "REPORT",
         "PROPPATCH",
         "UNLOCK",
         "OPTIONS",
         "CONNECT",
         "DELETE",
         "TRACE",
         "SEARCH",
         "HEAD",
         "COPY",
         "BMOVE",
         "GET",
         "PUT",
         "POST",
         "PROPFIND",
         "POLL"
      }

   A list of HTTP methods. Other methods will generate a weird. Note
   that the HTTP analyzer will only accept methods consisting solely
   of letters ``[A-Za-z]``.

.. bro:id:: HTTP::proxy_headers

   :Type: :bro:type:`set` [:bro:type:`string`]
   :Attributes: :bro:attr:`&redef`
   :Default:

   ::

      {
         "X-FORWARDED-FOR",
         "CLIENT-IP",
         "XROXY-CONNECTION",
         "X-FORWARDED-FROM",
         "FORWARDED",
         "PROXY-CONNECTION",
         "VIA"
      }

   A list of HTTP headers typically used to indicate proxied requests.

Types
#####
.. bro:type:: HTTP::Info

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
         Verb used in the HTTP request (GET, POST, HEAD, etc.).

      host: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value of the HOST header.

      uri: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         URI used in the request.

      referrer: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value of the "referer" header.  The comment is deliberately
         misspelled like the standard declares, but the name used here
         is "referrer" spelled correctly.

      version: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value of the version portion of the request.

      user_agent: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value of the User-Agent header from the client.

      origin: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Value of the Origin header from the client.

      request_body_len: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Actual uncompressed content size of the data transferred from
         the client.

      response_body_len: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Actual uncompressed content size of the data transferred from
         the server.

      status_code: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Status code returned by the server.

      status_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Status message returned by the server.

      info_code: :bro:type:`count` :bro:attr:`&log` :bro:attr:`&optional`
         Last seen 1xx informational reply code returned by the server.

      info_msg: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Last seen 1xx informational reply message returned by the server.

      tags: :bro:type:`set` [:bro:type:`HTTP::Tags`] :bro:attr:`&log`
         A set of indicators of various attributes discovered and
         related to a particular request/response pair.

      username: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Username if basic-auth is performed for the request.

      password: :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         Password if basic-auth is performed for the request.

      capture_password: :bro:type:`bool` :bro:attr:`&default` = :bro:see:`HTTP::default_capture_password` :bro:attr:`&optional`
         Determines if the password will be captured for this request.

      proxied: :bro:type:`set` [:bro:type:`string`] :bro:attr:`&log` :bro:attr:`&optional`
         All of the headers that may indicate if the request was proxied.

      range_request: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         Indicates if this request can assume 206 partial content in
         response.

      orig_fuids: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         An ordered vector of file unique IDs.
         Limited to :bro:see:`HTTP::max_files_orig` entries.

      orig_filenames: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         An ordered vector of filenames from the client.
         Limited to :bro:see:`HTTP::max_files_orig` entries.

      orig_mime_types: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         An ordered vector of mime types.
         Limited to :bro:see:`HTTP::max_files_orig` entries.

      resp_fuids: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         An ordered vector of file unique IDs.
         Limited to :bro:see:`HTTP::max_files_resp` entries.

      resp_filenames: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         An ordered vector of filenames from the server.
         Limited to :bro:see:`HTTP::max_files_resp` entries.

      resp_mime_types: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         An ordered vector of mime types.
         Limited to :bro:see:`HTTP::max_files_resp` entries.

      current_entity: :bro:type:`HTTP::Entity` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         The current entity.

      orig_mime_depth: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         Current number of MIME entities in the HTTP request message
         body.

      resp_mime_depth: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.bro` is loaded)

         Current number of MIME entities in the HTTP response message
         body.

      client_header_names: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/header-names.bro` is loaded)

         The vector of HTTP header names sent by the client.  No
         header values are included here, just the header names.

      server_header_names: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&log` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/header-names.bro` is loaded)

         The vector of HTTP header names sent by the server.  No
         header values are included here, just the header names.

      omniture: :bro:type:`bool` :bro:attr:`&default` = ``F`` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.bro` is loaded)

         Indicates if the server is an omniture advertising server.

      flash_version: :bro:type:`string` :bro:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.bro` is loaded)

         The unparsed Flash version, if detected.

      cookie_vars: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         (present if :doc:`/scripts/policy/protocols/http/var-extraction-cookies.bro` is loaded)

         Variable names extracted from all cookies.

      uri_vars: :bro:type:`vector` of :bro:type:`string` :bro:attr:`&optional` :bro:attr:`&log`
         (present if :doc:`/scripts/policy/protocols/http/var-extraction-uri.bro` is loaded)

         Variable names from the URI.

   The record type which contains the fields of the HTTP log.

.. bro:type:: HTTP::State

   :Type: :bro:type:`record`

      pending: :bro:type:`table` [:bro:type:`count`] of :bro:type:`HTTP::Info`
         Pending requests.

      current_request: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Current request in the pending queue.

      current_response: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Current response in the pending queue.

      trans_depth: :bro:type:`count` :bro:attr:`&default` = ``0`` :bro:attr:`&optional`
         Track the current deepest transaction.
         This is meant to cope with missing requests
         and responses.

   Structure to maintain state for an HTTP connection with multiple
   requests and responses.

.. bro:type:: HTTP::Tags

   :Type: :bro:type:`enum`

      .. bro:enum:: HTTP::EMPTY HTTP::Tags

         Placeholder.

      .. bro:enum:: HTTP::URI_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.bro` is loaded)


         Indicator of a URI based SQL injection attack.

      .. bro:enum:: HTTP::POST_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.bro` is loaded)


         Indicator of client body based SQL injection attack.  This is
         typically the body content of a POST request. Not implemented
         yet.

      .. bro:enum:: HTTP::COOKIE_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.bro` is loaded)


         Indicator of a cookie based SQL injection attack. Not
         implemented yet.

   Indicate a type of attack or compromise in the record to be logged.

Events
######
.. bro:id:: HTTP::log_http

   :Type: :bro:type:`event` (rec: :bro:type:`HTTP::Info`)

   Event that can be handled to access the HTTP record as it is sent on
   to the logging framework.


