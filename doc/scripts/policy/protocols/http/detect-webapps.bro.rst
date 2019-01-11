:tocdepth: 3

policy/protocols/http/detect-webapps.bro
========================================
.. bro:namespace:: HTTP

Detect and log web applications through the software framework.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/signatures </scripts/base/frameworks/signatures/index>`, :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinitions
#############
========================================================================= =
:bro:id:`Signatures::ignored_ids`: :bro:type:`pattern` :bro:attr:`&redef` 
:bro:type:`Software::Info`: :bro:type:`record`                            
:bro:type:`Software::Type`: :bro:type:`enum`                              
========================================================================= =


Detailed Interface
~~~~~~~~~~~~~~~~~~

