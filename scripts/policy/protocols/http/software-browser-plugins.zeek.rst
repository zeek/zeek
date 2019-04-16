:tocdepth: 3

policy/protocols/http/software-browser-plugins.zeek
===================================================
.. bro:namespace:: HTTP

Detect browser plugins as they leak through requests to Omniture
advertising servers.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ =
:bro:type:`HTTP::Info`: :bro:type:`record`   
:bro:type:`Software::Type`: :bro:type:`enum` 
============================================ =


Detailed Interface
~~~~~~~~~~~~~~~~~~

