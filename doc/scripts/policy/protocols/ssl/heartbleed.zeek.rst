:tocdepth: 3

policy/protocols/ssl/heartbleed.zeek
====================================
.. zeek:namespace:: Heartbleed

Detect the TLS heartbleed attack. See http://heartbleed.com for more.

:Namespace: Heartbleed
:Imports: :doc:`base/frameworks/notice </scripts/base/frameworks/notice/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
======================================================================================= ================================================================================================
:zeek:type:`Notice::Type`: :zeek:type:`enum`                                            
                                                                                        
                                                                                        * :zeek:enum:`Heartbleed::SSL_Heartbeat_Attack`:
                                                                                          Indicates that a host performed a heartbleed attack or scan.
                                                                                        
                                                                                        * :zeek:enum:`Heartbleed::SSL_Heartbeat_Attack_Success`:
                                                                                          Indicates that a host performing a heartbleed attack was probably successful.
                                                                                        
                                                                                        * :zeek:enum:`Heartbleed::SSL_Heartbeat_Many_Requests`:
                                                                                          Indicates we saw many heartbeat requests without a reply.
                                                                                        
                                                                                        * :zeek:enum:`Heartbleed::SSL_Heartbeat_Odd_Length`:
                                                                                          Indicates we saw heartbeat requests with odd length.
:zeek:type:`SSL::Info`: :zeek:type:`record`                                             
                                                                                        
                                                                                        :New Fields: :zeek:type:`SSL::Info`
                                                                                        
                                                                                          last_originator_heartbeat_request_size: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                        
                                                                                          last_responder_heartbeat_request_size: :zeek:type:`count` :zeek:attr:`&optional`
                                                                                        
                                                                                          originator_heartbeats: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                                                        
                                                                                          responder_heartbeats: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                                                        
                                                                                          heartbleed_detected: :zeek:type:`bool` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                                                        
                                                                                          enc_appdata_packages: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                                                        
                                                                                          enc_appdata_bytes: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
:zeek:id:`SSL::disable_analyzer_after_detection`: :zeek:type:`bool` :zeek:attr:`&redef` 
======================================================================================= ================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

