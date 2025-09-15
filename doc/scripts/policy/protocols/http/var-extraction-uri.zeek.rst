:tocdepth: 3

policy/protocols/http/var-extraction-uri.zeek
=============================================
.. zeek:namespace:: HTTP

Extracts and logs variables from the requested URI in the default HTTP
logging stream.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ===============================================================================================
:zeek:type:`HTTP::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`HTTP::Info`
                                             
                                               uri_vars: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                 Variable names from the URI.
============================================ ===============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

