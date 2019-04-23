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
============================================== =
:zeek:type:`HTTP::Info`: :zeek:type:`record`   
:zeek:type:`Software::Type`: :zeek:type:`enum` 
============================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

