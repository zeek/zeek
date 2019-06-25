:tocdepth: 3

base/protocols/http/main.zeek
=============================
.. zeek:namespace:: HTTP

Implements base functionality for HTTP analysis.  The logging model is
to log request/response pairs and all relevant metadata together in
a single record.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/tunnels </scripts/base/frameworks/tunnels/index>`, :doc:`base/utils/files.zeek </scripts/base/utils/files.zeek>`, :doc:`base/utils/numbers.zeek </scripts/base/utils/numbers.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================ ====================================================================
:zeek:id:`HTTP::default_capture_password`: :zeek:type:`bool` :zeek:attr:`&redef` This setting changes if passwords used in Basic-Auth are captured or
                                                                                 not.
:zeek:id:`HTTP::http_methods`: :zeek:type:`set` :zeek:attr:`&redef`              A list of HTTP methods.
:zeek:id:`HTTP::proxy_headers`: :zeek:type:`set` :zeek:attr:`&redef`             A list of HTTP headers typically used to indicate proxied requests.
================================================================================ ====================================================================

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
==================================================================== =
:zeek:type:`Log::ID`: :zeek:type:`enum`                              
:zeek:type:`connection`: :zeek:type:`record`                         
:zeek:id:`likely_server_ports`: :zeek:type:`set` :zeek:attr:`&redef` 
==================================================================== =

Events
######
============================================= ====================================================================
:zeek:id:`HTTP::log_http`: :zeek:type:`event` Event that can be handled to access the HTTP record as it is sent on
                                              to the logging framework.
============================================= ====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: HTTP::default_capture_password

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   This setting changes if passwords used in Basic-Auth are captured or
   not.

.. zeek:id:: HTTP::http_methods

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
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

.. zeek:id:: HTTP::proxy_headers

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
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
.. zeek:type:: HTTP::Info

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
         Verb used in the HTTP request (GET, POST, HEAD, etc.).

      host: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value of the HOST header.

      uri: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         URI used in the request.

      referrer: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value of the "referer" header.  The comment is deliberately
         misspelled like the standard declares, but the name used here
         is "referrer" spelled correctly.

      version: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value of the version portion of the request.

      user_agent: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value of the User-Agent header from the client.

      origin: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Value of the Origin header from the client.

      request_body_len: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Actual uncompressed content size of the data transferred from
         the client.

      response_body_len: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Actual uncompressed content size of the data transferred from
         the server.

      status_code: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Status code returned by the server.

      status_msg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Status message returned by the server.

      info_code: :zeek:type:`count` :zeek:attr:`&log` :zeek:attr:`&optional`
         Last seen 1xx informational reply code returned by the server.

      info_msg: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Last seen 1xx informational reply message returned by the server.

      tags: :zeek:type:`set` [:zeek:type:`HTTP::Tags`] :zeek:attr:`&log`
         A set of indicators of various attributes discovered and
         related to a particular request/response pair.

      username: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Username if basic-auth is performed for the request.

      password: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Password if basic-auth is performed for the request.

      capture_password: :zeek:type:`bool` :zeek:attr:`&default` = :zeek:see:`HTTP::default_capture_password` :zeek:attr:`&optional`
         Determines if the password will be captured for this request.

      proxied: :zeek:type:`set` [:zeek:type:`string`] :zeek:attr:`&log` :zeek:attr:`&optional`
         All of the headers that may indicate if the request was proxied.

      range_request: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicates if this request can assume 206 partial content in
         response.

      orig_fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         An ordered vector of file unique IDs.
         Limited to :zeek:see:`HTTP::max_files_orig` entries.

      orig_filenames: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         An ordered vector of filenames from the client.
         Limited to :zeek:see:`HTTP::max_files_orig` entries.

      orig_mime_types: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         An ordered vector of mime types.
         Limited to :zeek:see:`HTTP::max_files_orig` entries.

      resp_fuids: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         An ordered vector of file unique IDs.
         Limited to :zeek:see:`HTTP::max_files_resp` entries.

      resp_filenames: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         An ordered vector of filenames from the server.
         Limited to :zeek:see:`HTTP::max_files_resp` entries.

      resp_mime_types: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         An ordered vector of mime types.
         Limited to :zeek:see:`HTTP::max_files_resp` entries.

      current_entity: :zeek:type:`HTTP::Entity` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         The current entity.

      orig_mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         Current number of MIME entities in the HTTP request message
         body.

      resp_mime_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/base/protocols/http/entities.zeek` is loaded)

         Current number of MIME entities in the HTTP response message
         body.

      client_header_names: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/header-names.zeek` is loaded)

         The vector of HTTP header names sent by the client.  No
         header values are included here, just the header names.

      server_header_names: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/header-names.zeek` is loaded)

         The vector of HTTP header names sent by the server.  No
         header values are included here, just the header names.

      omniture: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.zeek` is loaded)

         Indicates if the server is an omniture advertising server.

      flash_version: :zeek:type:`string` :zeek:attr:`&optional`
         (present if :doc:`/scripts/policy/protocols/http/software-browser-plugins.zeek` is loaded)

         The unparsed Flash version, if detected.

      cookie_vars: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         (present if :doc:`/scripts/policy/protocols/http/var-extraction-cookies.zeek` is loaded)

         Variable names extracted from all cookies.

      uri_vars: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
         (present if :doc:`/scripts/policy/protocols/http/var-extraction-uri.zeek` is loaded)

         Variable names from the URI.

   The record type which contains the fields of the HTTP log.

.. zeek:type:: HTTP::State

   :Type: :zeek:type:`record`

      pending: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`HTTP::Info`
         Pending requests.

      current_request: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Current request in the pending queue.

      current_response: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Current response in the pending queue.

      trans_depth: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
         Track the current deepest transaction.
         This is meant to cope with missing requests
         and responses.

   Structure to maintain state for an HTTP connection with multiple
   requests and responses.

.. zeek:type:: HTTP::Tags

   :Type: :zeek:type:`enum`

      .. zeek:enum:: HTTP::EMPTY HTTP::Tags

         Placeholder.

      .. zeek:enum:: HTTP::URI_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicator of a URI based SQL injection attack.

      .. zeek:enum:: HTTP::POST_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicator of client body based SQL injection attack.  This is
         typically the body content of a POST request. Not implemented
         yet.

      .. zeek:enum:: HTTP::COOKIE_SQLI HTTP::Tags

         (present if :doc:`/scripts/policy/protocols/http/detect-sqli.zeek` is loaded)


         Indicator of a cookie based SQL injection attack. Not
         implemented yet.

   Indicate a type of attack or compromise in the record to be logged.

Events
######
.. zeek:id:: HTTP::log_http

   :Type: :zeek:type:`event` (rec: :zeek:type:`HTTP::Info`)

   Event that can be handled to access the HTTP record as it is sent on
   to the logging framework.


