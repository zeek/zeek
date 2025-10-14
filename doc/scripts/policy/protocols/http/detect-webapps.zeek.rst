:tocdepth: 3

policy/protocols/http/detect-webapps.zeek
=========================================
.. zeek:namespace:: HTTP

Detect and log web applications through the software framework.

:Namespace: HTTP
:Imports: :doc:`base/frameworks/signatures </scripts/base/frameworks/signatures/index>`, :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`base/protocols/http </scripts/base/protocols/http/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================================================ ===================================================================
:zeek:id:`Signatures::ignored_ids`: :zeek:type:`pattern` :zeek:attr:`&redef` 
:zeek:type:`Software::Info`: :zeek:type:`record`                             
                                                                             
                                                                             :New Fields: :zeek:type:`Software::Info`
                                                                             
                                                                               url: :zeek:type:`string` :zeek:attr:`&optional` :zeek:attr:`&log`
                                                                                 Most root URL where the software was discovered.
:zeek:type:`Software::Type`: :zeek:type:`enum`                               
                                                                             
                                                                             * :zeek:enum:`HTTP::WEB_APPLICATION`:
                                                                               Identifier for web applications in the software framework.
============================================================================ ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

