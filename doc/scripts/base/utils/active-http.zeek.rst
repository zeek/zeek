:tocdepth: 3

base/utils/active-http.zeek
===========================
.. zeek:namespace:: ActiveHTTP

A module for performing active HTTP requests and
getting the reply at runtime.

:Namespace: ActiveHTTP
:Imports: :doc:`base/utils/exec.zeek </scripts/base/utils/exec.zeek>`

Summary
~~~~~~~
Runtime Options
###############
================================================================================== =================================================
:zeek:id:`ActiveHTTP::default_max_time`: :zeek:type:`interval` :zeek:attr:`&redef` The default timeout for HTTP requests.
:zeek:id:`ActiveHTTP::default_method`: :zeek:type:`string` :zeek:attr:`&redef`     The default HTTP method/verb to use for requests.
================================================================================== =================================================

Types
#####
====================================================== =
:zeek:type:`ActiveHTTP::Request`: :zeek:type:`record`
:zeek:type:`ActiveHTTP::Response`: :zeek:type:`record`
====================================================== =

Functions
#########
===================================================== ========================================
:zeek:id:`ActiveHTTP::request`: :zeek:type:`function` Perform an HTTP request according to the
                                                      :zeek:type:`ActiveHTTP::Request` record.
===================================================== ========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: ActiveHTTP::default_max_time
   :source-code: base/utils/active-http.zeek 10 10

   :Type: :zeek:type:`interval`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``1.0 min``

   The default timeout for HTTP requests.

.. zeek:id:: ActiveHTTP::default_method
   :source-code: base/utils/active-http.zeek 13 13

   :Type: :zeek:type:`string`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``"GET"``

   The default HTTP method/verb to use for requests.

Types
#####
.. zeek:type:: ActiveHTTP::Request
   :source-code: base/utils/active-http.zeek 26 46

   :Type: :zeek:type:`record`


   .. zeek:field:: url :zeek:type:`string`

      The URL being requested.


   .. zeek:field:: method :zeek:type:`string` :zeek:attr:`&default` = :zeek:see:`ActiveHTTP::default_method` :zeek:attr:`&optional`

      The HTTP method/verb to use for the request.


   .. zeek:field:: client_data :zeek:type:`string` :zeek:attr:`&optional`

      Data to send to the server in the client body.  Keep in
      mind that you will probably need to set the *method* field
      to "POST" or "PUT".


   .. zeek:field:: max_time :zeek:type:`interval` :zeek:attr:`&default` = :zeek:see:`ActiveHTTP::default_max_time` :zeek:attr:`&optional`

      Timeout for the request.


   .. zeek:field:: addl_curl_args :zeek:type:`string` :zeek:attr:`&optional`

      Additional curl command line arguments.  Be very careful
      with this option since shell injection could take place
      if careful handling of untrusted data is not applied.



.. zeek:type:: ActiveHTTP::Response
   :source-code: base/utils/active-http.zeek 15 24

   :Type: :zeek:type:`record`


   .. zeek:field:: code :zeek:type:`count`

      Numeric response code from the server.


   .. zeek:field:: msg :zeek:type:`string`

      String response message from the server.


   .. zeek:field:: body :zeek:type:`string` :zeek:attr:`&optional`

      Full body of the response.


   .. zeek:field:: headers :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`string` :zeek:attr:`&optional`

      All headers returned by the server.



Functions
#########
.. zeek:id:: ActiveHTTP::request
   :source-code: base/utils/active-http.zeek 79 135

   :Type: :zeek:type:`function` (req: :zeek:type:`ActiveHTTP::Request`) : :zeek:type:`ActiveHTTP::Response`

   Perform an HTTP request according to the
   :zeek:type:`ActiveHTTP::Request` record.  This is an asynchronous
   function and must be called within a "when" statement.


   :param req: A record instance representing all options for an HTTP request.


   :returns: A record with the full response message.


