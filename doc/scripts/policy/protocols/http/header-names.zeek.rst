:tocdepth: 3

policy/protocols/http/header-names.zeek
=======================================
.. zeek:namespace:: HTTP

Extract and include the header names used for each request in the HTTP
logging stream.  The headers in the logging stream will be stored in the
same order which they were seen on the wire.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=============================================================================== =====================================================================
:zeek:id:`HTTP::log_client_header_names`: :zeek:type:`bool` :zeek:attr:`&redef` A boolean value to determine if client header names are to be logged.
:zeek:id:`HTTP::log_server_header_names`: :zeek:type:`bool` :zeek:attr:`&redef` A boolean value to determine if server header names are to be logged.
=============================================================================== =====================================================================

Redefinitions
#############
============================================ ==========================================================================================================
:zeek:type:`HTTP::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`HTTP::Info`
                                             
                                               client_header_names: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 The vector of HTTP header names sent by the client.
                                             
                                               server_header_names: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 The vector of HTTP header names sent by the server.
============================================ ==========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: HTTP::log_client_header_names
   :source-code: policy/protocols/http/header-names.zeek 21 21

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``T``

   A boolean value to determine if client header names are to be logged.

.. zeek:id:: HTTP::log_server_header_names
   :source-code: policy/protocols/http/header-names.zeek 24 24

   :Type: :zeek:type:`bool`
   :Attributes: :zeek:attr:`&redef`
   :Default: ``F``

   A boolean value to determine if server header names are to be logged.


