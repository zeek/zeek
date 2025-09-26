:tocdepth: 3

policy/protocols/http/software-browser-plugins.zeek
===================================================
.. zeek:namespace:: HTTP

Detect browser plugins as they leak through requests to Omniture
advertising servers.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================== ==================================================================================
:zeek:type:`HTTP::Info`: :zeek:type:`record`   
                                               
                                               :New Fields: :zeek:type:`HTTP::Info`
                                               
                                                 omniture: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                   Indicates if the server is an omniture advertising server.
                                               
                                                 flash_version: :zeek:type:`string` :zeek:attr:`&optional`
                                                   The unparsed Flash version, if detected.
:zeek:type:`Software::Type`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`HTTP::BROWSER_PLUGIN`:
                                                 Identifier for browser plugins in the software framework.
============================================== ==================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

