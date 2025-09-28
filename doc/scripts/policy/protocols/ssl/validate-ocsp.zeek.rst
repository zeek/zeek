:tocdepth: 3

policy/protocols/ssl/validate-ocsp.zeek
=======================================
.. zeek:namespace:: SSL

Perform validation of stapled OCSP responses.

:Namespace: SSL
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ===========================================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
                                             
                                             * :zeek:enum:`SSL::Invalid_Ocsp_Response`:
                                               This indicates that the OCSP response was not deemed
                                               to be valid.
:zeek:type:`SSL::Info`: :zeek:type:`record`  
                                             
                                             :New Fields: :zeek:type:`SSL::Info`
                                             
                                               ocsp_status: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Result of ocsp validation for this connection.
                                             
                                               ocsp_response: :zeek:type:`string` :zeek:attr:`&optional`
                                                 ocsp response as string.
============================================ ===========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

