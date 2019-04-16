:tocdepth: 3

policy/protocols/http/header-names.zeek
=======================================
.. bro:namespace:: HTTP

Extract and include the header names used for each request in the HTTP
logging stream.  The headers in the logging stream will be stored in the
same order which they were seen on the wire.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`

Summary
~~~~~~~
Runtime Options
###############
============================================================================ =====================================================================
:bro:id:`HTTP::log_client_header_names`: :bro:type:`bool` :bro:attr:`&redef` A boolean value to determine if client header names are to be logged.
:bro:id:`HTTP::log_server_header_names`: :bro:type:`bool` :bro:attr:`&redef` A boolean value to determine if server header names are to be logged.
============================================================================ =====================================================================

Redefinitions
#############
========================================== =
:bro:type:`HTTP::Info`: :bro:type:`record` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. bro:id:: HTTP::log_client_header_names

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``T``

   A boolean value to determine if client header names are to be logged.

.. bro:id:: HTTP::log_server_header_names

   :Type: :bro:type:`bool`
   :Attributes: :bro:attr:`&redef`
   :Default: ``F``

   A boolean value to determine if server header names are to be logged.


