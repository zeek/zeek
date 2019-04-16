:tocdepth: 3

base/utils/active-http.zeek
===========================
.. bro:namespace:: ActiveHTTP

A module for performing active HTTP requests and
getting the reply at runtime.

:Namespace: ActiveHTTP
:Imports: :doc:`base/utils/exec.zeek </scripts/base/utils/exec.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== =================================================
:bro:id:`ActiveHTTP::default_max_time`: :bro:type:`interval` :bro:attr:`&redef` The default timeout for HTTP requests.
:bro:id:`ActiveHTTP::default_method`: :bro:type:`string` :bro:attr:`&redef`     The default HTTP method/verb to use for requests.
=============================================================================== =================================================

Types
#####
==================================================== =
:bro:type:`ActiveHTTP::Request`: :bro:type:`record`  
:bro:type:`ActiveHTTP::Response`: :bro:type:`record` 
==================================================== =

Functions
#########
=================================================== ========================================
:bro:id:`ActiveHTTP::request`: :bro:type:`function` Perform an HTTP request according to the
                                                    :bro:type:`ActiveHTTP::Request` record.
=================================================== ========================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: ActiveHTTP::default_max_time

   :Type: :bro:type:`interval`
   :Attributes: :bro:attr:`&redef`
   :Default: ``1.0 min``

   The default timeout for HTTP requests.

.. bro:id:: ActiveHTTP::default_method

   :Type: :bro:type:`string`
   :Attributes: :bro:attr:`&redef`
   :Default: ``"GET"``

   The default HTTP method/verb to use for requests.

Types
#####
.. bro:type:: ActiveHTTP::Request

   :Type: :bro:type:`record`

      url: :bro:type:`string`
         The URL being requested.

      method: :bro:type:`string` :bro:attr:`&default` = :bro:see:`ActiveHTTP::default_method` :bro:attr:`&optional`
         The HTTP method/verb to use for the request.

      client_data: :bro:type:`string` :bro:attr:`&optional`
         Data to send to the server in the client body.  Keep in
         mind that you will probably need to set the *method* field
         to "POST" or "PUT".

      max_time: :bro:type:`interval` :bro:attr:`&default` = :bro:see:`ActiveHTTP::default_max_time` :bro:attr:`&optional`
         Timeout for the request.

      addl_curl_args: :bro:type:`string` :bro:attr:`&optional`
         Additional curl command line arguments.  Be very careful
         with this option since shell injection could take place
         if careful handling of untrusted data is not applied.


.. bro:type:: ActiveHTTP::Response

   :Type: :bro:type:`record`

      code: :bro:type:`count`
         Numeric response code from the server.

      msg: :bro:type:`string`
         String response message from the server.

      body: :bro:type:`string` :bro:attr:`&optional`
         Full body of the response.

      headers: :bro:type:`table` [:bro:type:`string`] of :bro:type:`string` :bro:attr:`&optional`
         All headers returned by the server.


Functions
#########
.. bro:id:: ActiveHTTP::request

   :Type: :bro:type:`function` (req: :bro:type:`ActiveHTTP::Request`) : :bro:type:`ActiveHTTP::Response`

   Perform an HTTP request according to the
   :bro:type:`ActiveHTTP::Request` record.  This is an asynchronous
   function and must be called within a "when" statement.
   

   :req: A record instance representing all options for an HTTP request.
   

   :returns: A record with the full response message.


