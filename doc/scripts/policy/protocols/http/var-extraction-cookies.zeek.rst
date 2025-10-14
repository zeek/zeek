:tocdepth: 3

policy/protocols/http/var-extraction-cookies.zeek
=================================================
.. zeek:namespace:: HTTP

Extracts and logs variable names from cookies sent by clients.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/protocols/http/utils.zeek </scripts/base/protocols/http/utils.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ==================================================================================================
:zeek:type:`HTTP::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`HTTP::Info`
                                             
                                               cookie_vars: :zeek:type:`vector` of :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                 Variable names extracted from all cookies.
============================================ ==================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

