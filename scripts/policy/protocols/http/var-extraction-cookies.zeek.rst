:tocdepth: 3

policy/protocols/http/var-extraction-cookies.zeek
=================================================
.. bro:namespace:: HTTP

Extracts and logs variable names from cookies sent by clients.

:Namespace: HTTP
:Imports: :doc:`base/protocols/http/main.zeek </scripts/base/protocols/http/main.zeek>`, :doc:`base/protocols/http/utils.zeek </scripts/base/protocols/http/utils.zeek>`

Summary
~~~~~~~
Redefinitions
#############
========================================== =
:bro:type:`HTTP::Info`: :bro:type:`record` 
========================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~

