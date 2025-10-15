:tocdepth: 3

base/protocols/ssl/consts.zeek
==============================
.. zeek:namespace:: SSL


:Namespace: SSL

Summary
~~~~~~~
Constants
#########
====================================================================================================== =====================================================================================
:zeek:id:`SSL::ALERT`: :zeek:type:`count`                                                              
:zeek:id:`SSL::APPLICATION_DATA`: :zeek:type:`count`                                                   
:zeek:id:`SSL::CERTIFICATE`: :zeek:type:`count`                                                        
:zeek:id:`SSL::CERTIFICATE_REQUEST`: :zeek:type:`count`                                                
:zeek:id:`SSL::CERTIFICATE_STATUS`: :zeek:type:`count`                                                 
:zeek:id:`SSL::CERTIFICATE_URL`: :zeek:type:`count`                                                    
:zeek:id:`SSL::CERTIFICATE_VERIFY`: :zeek:type:`count`                                                 
:zeek:id:`SSL::CHANGE_CIPHER_SPEC`: :zeek:type:`count`                                                 
:zeek:id:`SSL::CLIENT_HELLO`: :zeek:type:`count`                                                       
:zeek:id:`SSL::CLIENT_KEY_EXCHANGE`: :zeek:type:`count`                                                
:zeek:id:`SSL::DTLSv10`: :zeek:type:`count`                                                            
:zeek:id:`SSL::DTLSv12`: :zeek:type:`count`                                                            
:zeek:id:`SSL::DTLSv13`: :zeek:type:`count`                                                            
:zeek:id:`SSL::ENCRYPTED_EXTENSIONS`: :zeek:type:`count`                                               
:zeek:id:`SSL::FINISHED`: :zeek:type:`count`                                                           
:zeek:id:`SSL::HANDSHAKE`: :zeek:type:`count`                                                          
:zeek:id:`SSL::HEARTBEAT`: :zeek:type:`count`                                                          
:zeek:id:`SSL::HELLO_REQUEST`: :zeek:type:`count`                                                      
:zeek:id:`SSL::HELLO_RETRY_REQUEST`: :zeek:type:`count`                                                
:zeek:id:`SSL::HELLO_VERIFY_REQUEST`: :zeek:type:`count`                                               
:zeek:id:`SSL::KEY_UPDATE`: :zeek:type:`count`                                                         
:zeek:id:`SSL::SERVER_HELLO`: :zeek:type:`count`                                                       
:zeek:id:`SSL::SERVER_HELLO_DONE`: :zeek:type:`count`                                                  
:zeek:id:`SSL::SERVER_KEY_EXCHANGE`: :zeek:type:`count`                                                
:zeek:id:`SSL::SESSION_TICKET`: :zeek:type:`count`                                                     
:zeek:id:`SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION`: :zeek:type:`count`               
:zeek:id:`SSL::SSL_EXTENSION_APPLICATION_SETTING`: :zeek:type:`count`                                  
:zeek:id:`SSL::SSL_EXTENSION_CACHED_INFO`: :zeek:type:`count`                                          
:zeek:id:`SSL::SSL_EXTENSION_CERTIFICATE_AUTHORITIES`: :zeek:type:`count`                              
:zeek:id:`SSL::SSL_EXTENSION_CERT_TYPE`: :zeek:type:`count`                                            
:zeek:id:`SSL::SSL_EXTENSION_CHANNEL_ID`: :zeek:type:`count`                                           
:zeek:id:`SSL::SSL_EXTENSION_CHANNEL_ID_NEW`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_CLIENT_AUTHZ`: :zeek:type:`count`                                         
:zeek:id:`SSL::SSL_EXTENSION_CLIENT_CERTIFICATE_TYPE`: :zeek:type:`count`                              
:zeek:id:`SSL::SSL_EXTENSION_CLIENT_CERTIFICATE_URL`: :zeek:type:`count`                               
:zeek:id:`SSL::SSL_EXTENSION_COMPRESS_CERTIFICATE`: :zeek:type:`count`                                 
:zeek:id:`SSL::SSL_EXTENSION_CONNECTION_ID`: :zeek:type:`count`                                        
:zeek:id:`SSL::SSL_EXTENSION_CONNECTION_ID_DEPRECATED`: :zeek:type:`count`                             
:zeek:id:`SSL::SSL_EXTENSION_COOKIE`: :zeek:type:`count`                                               
:zeek:id:`SSL::SSL_EXTENSION_DELEGATED_CREDENTIAL`: :zeek:type:`count`                                 
:zeek:id:`SSL::SSL_EXTENSION_DNSSEC_CHAIN`: :zeek:type:`count`                                         
:zeek:id:`SSL::SSL_EXTENSION_EARLY_DATA`: :zeek:type:`count`                                           
:zeek:id:`SSL::SSL_EXTENSION_EC_POINT_FORMATS`: :zeek:type:`count`                                     
:zeek:id:`SSL::SSL_EXTENSION_ENCRYPTED_CLIENT_CERTIFICATES`: :zeek:type:`count`                        
:zeek:id:`SSL::SSL_EXTENSION_ENCRYPTED_CLIENT_HELLO`: :zeek:type:`count`                               
:zeek:id:`SSL::SSL_EXTENSION_ENCRYPT_THEN_MAC`: :zeek:type:`count`                                     
:zeek:id:`SSL::SSL_EXTENSION_EXTENDED_MASTER_SECRET`: :zeek:type:`count`                               
:zeek:id:`SSL::SSL_EXTENSION_EXTERNAL_ID_HASH`: :zeek:type:`count`                                     
:zeek:id:`SSL::SSL_EXTENSION_EXTERNAL_SESSION_ID`: :zeek:type:`count`                                  
:zeek:id:`SSL::SSL_EXTENSION_HEARTBEAT`: :zeek:type:`count`                                            
:zeek:id:`SSL::SSL_EXTENSION_KEY_SHARE`: :zeek:type:`count`                                            
:zeek:id:`SSL::SSL_EXTENSION_KEY_SHARE_OLD`: :zeek:type:`count`                                        
:zeek:id:`SSL::SSL_EXTENSION_MAX_FRAGMENT_LENGTH`: :zeek:type:`count`                                  
:zeek:id:`SSL::SSL_EXTENSION_NEXT_PROTOCOL_NEGOTIATION`: :zeek:type:`count`                            
:zeek:id:`SSL::SSL_EXTENSION_OID_FILTERS`: :zeek:type:`count`                                          
:zeek:id:`SSL::SSL_EXTENSION_ORIGIN_BOUND_CERTIFICATES`: :zeek:type:`count`                            
:zeek:id:`SSL::SSL_EXTENSION_PADDING`: :zeek:type:`count`                                              
:zeek:id:`SSL::SSL_EXTENSION_PADDING_TEMP`: :zeek:type:`count`                                         
:zeek:id:`SSL::SSL_EXTENSION_PASSWORD_SALT`: :zeek:type:`count`                                        
:zeek:id:`SSL::SSL_EXTENSION_POST_HANDSHAKE_AUTH`: :zeek:type:`count`                                  
:zeek:id:`SSL::SSL_EXTENSION_PRE_SHARED_KEY`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_PSK_KEY_EXCHANGE_MODES`: :zeek:type:`count`                               
:zeek:id:`SSL::SSL_EXTENSION_PWD_CLEAR`: :zeek:type:`count`                                            
:zeek:id:`SSL::SSL_EXTENSION_PWD_PROTECT`: :zeek:type:`count`                                          
:zeek:id:`SSL::SSL_EXTENSION_QUIC_TRANSPORT_PARAMETERS`: :zeek:type:`count`                            
:zeek:id:`SSL::SSL_EXTENSION_RECORD_SIZE_LIMIT`: :zeek:type:`count`                                    
:zeek:id:`SSL::SSL_EXTENSION_RENEGOTIATION_INFO`: :zeek:type:`count`                                   
:zeek:id:`SSL::SSL_EXTENSION_SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS`: :zeek:type:`count`                
:zeek:id:`SSL::SSL_EXTENSION_SERVER_AUTHZ`: :zeek:type:`count`                                         
:zeek:id:`SSL::SSL_EXTENSION_SERVER_CERTIFICATE_TYPE`: :zeek:type:`count`                              
:zeek:id:`SSL::SSL_EXTENSION_SERVER_NAME`: :zeek:type:`count`                                          
:zeek:id:`SSL::SSL_EXTENSION_SESSIONTICKET_TLS`: :zeek:type:`count`                                    
:zeek:id:`SSL::SSL_EXTENSION_SIGNATURE_ALGORITHMS`: :zeek:type:`count`                                 
:zeek:id:`SSL::SSL_EXTENSION_SIGNATURE_ALGORITHMS_CERT`: :zeek:type:`count`                            
:zeek:id:`SSL::SSL_EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP`: :zeek:type:`count`                         
:zeek:id:`SSL::SSL_EXTENSION_SRP`: :zeek:type:`count`                                                  
:zeek:id:`SSL::SSL_EXTENSION_STATUS_REQUEST`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_STATUS_REQUEST_V2`: :zeek:type:`count`                                    
:zeek:id:`SSL::SSL_EXTENSION_SUPPORTED_EKT_CIPHERS`: :zeek:type:`count`                                
:zeek:id:`SSL::SSL_EXTENSION_SUPPORTED_GROUPS`: :zeek:type:`count`                                     
:zeek:id:`SSL::SSL_EXTENSION_SUPPORTED_VERSIONS`: :zeek:type:`count`                                   
:zeek:id:`SSL::SSL_EXTENSION_TICKETEARLYDATAINFO`: :zeek:type:`count`                                  
:zeek:id:`SSL::SSL_EXTENSION_TICKET_PINNING`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_TICKET_REQUEST`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_TLMSP`: :zeek:type:`count`                                                
:zeek:id:`SSL::SSL_EXTENSION_TLMSP_DELEGATE`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_TLMSP_PROXYING`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_TLS_CERT_WITH_EXTERN_PSK`: :zeek:type:`count`                             
:zeek:id:`SSL::SSL_EXTENSION_TLS_LTS`: :zeek:type:`count`                                              
:zeek:id:`SSL::SSL_EXTENSION_TOKEN_BINDING`: :zeek:type:`count`                                        
:zeek:id:`SSL::SSL_EXTENSION_TRANSPARENCY_INFO`: :zeek:type:`count`                                    
:zeek:id:`SSL::SSL_EXTENSION_TRUNCATED_HMAC`: :zeek:type:`count`                                       
:zeek:id:`SSL::SSL_EXTENSION_TRUSTED_CA_KEYS`: :zeek:type:`count`                                      
:zeek:id:`SSL::SSL_EXTENSION_USER_MAPPING`: :zeek:type:`count`                                         
:zeek:id:`SSL::SSL_EXTENSION_USE_SRTP`: :zeek:type:`count`                                             
:zeek:id:`SSL::SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA`: :zeek:type:`count`                             
:zeek:id:`SSL::SSL_FORTEZZA_KEA_WITH_NULL_SHA`: :zeek:type:`count`                                     
:zeek:id:`SSL::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2`: :zeek:type:`count`                               
:zeek:id:`SSL::SSL_RSA_FIPS_WITH_DES_CBC_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::SSL_RSA_FIPS_WITH_DES_CBC_SHA_2`: :zeek:type:`count`                                    
:zeek:id:`SSL::SSL_RSA_WITH_3DES_EDE_CBC_MD5`: :zeek:type:`count`                                      
:zeek:id:`SSL::SSL_RSA_WITH_DES_CBC_MD5`: :zeek:type:`count`                                           
:zeek:id:`SSL::SSL_RSA_WITH_IDEA_CBC_MD5`: :zeek:type:`count`                                          
:zeek:id:`SSL::SSL_RSA_WITH_RC2_CBC_MD5`: :zeek:type:`count`                                           
:zeek:id:`SSL::SSLv2`: :zeek:type:`count`                                                              
:zeek:id:`SSL::SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5`: :zeek:type:`count`                                
:zeek:id:`SSL::SSLv20_CK_DES_64_CBC_WITH_MD5`: :zeek:type:`count`                                      
:zeek:id:`SSL::SSLv20_CK_IDEA_128_CBC_WITH_MD5`: :zeek:type:`count`                                    
:zeek:id:`SSL::SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5`: :zeek:type:`count`                            
:zeek:id:`SSL::SSLv20_CK_RC2_128_CBC_WITH_MD5`: :zeek:type:`count`                                     
:zeek:id:`SSL::SSLv20_CK_RC4_128_EXPORT40_WITH_MD5`: :zeek:type:`count`                                
:zeek:id:`SSL::SSLv20_CK_RC4_128_WITH_MD5`: :zeek:type:`count`                                         
:zeek:id:`SSL::SSLv3`: :zeek:type:`count`                                                              
:zeek:id:`SSL::SUPPLEMENTAL_DATA`: :zeek:type:`count`                                                  
:zeek:id:`SSL::TLS_AEGIS_128L_SHA256`: :zeek:type:`count`                                              
:zeek:id:`SSL::TLS_AEGIS_256_SHA384`: :zeek:type:`count`                                               
:zeek:id:`SSL::TLS_AES_128_CCM_8_SHA256`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_AES_128_CCM_SHA256`: :zeek:type:`count`                                             
:zeek:id:`SSL::TLS_AES_128_GCM_SHA256`: :zeek:type:`count`                                             
:zeek:id:`SSL::TLS_AES_256_GCM_SHA384`: :zeek:type:`count`                                             
:zeek:id:`SSL::TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                     
:zeek:id:`SSL::TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                       
:zeek:id:`SSL::TLS_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_128_CBC_RMD`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_256_CBC_RMD`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_DSS_WITH_DES_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_DSS_WITH_RC4_128_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_DSS_WITH_SEED_CBC_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_128_CCM`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_256_CCM`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_DHE_PSK_WITH_NULL_SHA256`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_PSK_WITH_NULL_SHA384`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_PSK_WITH_RC4_128_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_128_CBC_RMD`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_128_CCM`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_128_CCM_8`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_256_CBC_RMD`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_256_CCM`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_256_CCM_8`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD`: :zeek:type:`count`                      
:zeek:id:`SSL::TLS_DHE_RSA_WITH_DES_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DHE_RSA_WITH_SEED_CBC_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_DH_ANON_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DH_ANON_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_ANON_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_ANON_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DH_ANON_WITH_AES_256_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_ANON_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_DH_ANON_WITH_DES_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DH_ANON_WITH_RC4_128_MD5`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DH_ANON_WITH_SEED_CBC_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DH_DSS_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_DH_DSS_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_DSS_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_DSS_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_DH_DSS_WITH_AES_256_CBC_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_DSS_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_DSS_WITH_DES_CBC_SHA`: :zeek:type:`count`                                        
:zeek:id:`SSL::TLS_DH_DSS_WITH_SEED_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_DH_RSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_DH_RSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_RSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_RSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_DH_RSA_WITH_AES_256_CBC_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_RSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_DH_RSA_WITH_DES_CBC_SHA`: :zeek:type:`count`                                        
:zeek:id:`SSL::TLS_DH_RSA_WITH_SEED_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_ECCPWD_WITH_AES_128_CCM_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECCPWD_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECCPWD_WITH_AES_256_CCM_SHA384`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECCPWD_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CCM`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CCM`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                       
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                       
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                       
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                       
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                      
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD`: :zeek:type:`count`                  
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_NULL_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256_OLD`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                         
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                         
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                        
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_NULL_SHA`: :zeek:type:`count`                                        
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_NULL_SHA256`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_NULL_SHA384`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_ECDHE_PSK_WITH_RC4_128_SHA`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                         
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                         
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                         
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                         
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                        
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD`: :zeek:type:`count`                    
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_NULL_SHA`: :zeek:type:`count`                                        
:zeek:id:`SSL::TLS_ECDHE_RSA_WITH_RC4_128_SHA`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDH_ANON_WITH_NULL_SHA`: :zeek:type:`count`                                        
:zeek:id:`SSL::TLS_ECDH_ANON_WITH_RC4_128_SHA`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                        
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                        
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                        
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                        
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_NULL_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_ECDH_ECDSA_WITH_RC4_128_SHA`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_NULL_SHA`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_ECDH_RSA_WITH_RC4_128_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_EMPTY_RENEGOTIATION_INFO_SCSV`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_FALLBACK_SCSV`: :zeek:type:`count`                                                  
:zeek:id:`SSL::TLS_GOSTR341001_WITH_28147_CNT_IMIT`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_GOSTR341001_WITH_NULL_GOSTR3411`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_GOSTR341094_WITH_28147_CNT_IMIT`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_GOSTR341094_WITH_NULL_GOSTR3411`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_28147_CNT_IMIT`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC`: :zeek:type:`count`                       
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC`: :zeek:type:`count`                            
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_KRB5_EXPORT_WITH_RC4_40_MD5`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_KRB5_EXPORT_WITH_RC4_40_SHA`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_KRB5_WITH_3DES_EDE_CBC_MD5`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_KRB5_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_KRB5_WITH_DES_CBC_MD5`: :zeek:type:`count`                                          
:zeek:id:`SSL::TLS_KRB5_WITH_DES_CBC_SHA`: :zeek:type:`count`                                          
:zeek:id:`SSL::TLS_KRB5_WITH_IDEA_CBC_MD5`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_KRB5_WITH_IDEA_CBC_SHA`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_KRB5_WITH_RC4_128_MD5`: :zeek:type:`count`                                          
:zeek:id:`SSL::TLS_KRB5_WITH_RC4_128_SHA`: :zeek:type:`count`                                          
:zeek:id:`SSL::TLS_NULL_WITH_NULL_NULL`: :zeek:type:`count`                                            
:zeek:id:`SSL::TLS_PSK_DHE_WITH_AES_128_CCM_8`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_PSK_DHE_WITH_AES_256_CCM_8`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_PSK_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_PSK_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_PSK_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_PSK_WITH_AES_128_CCM`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_PSK_WITH_AES_128_CCM_8`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_PSK_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_PSK_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_PSK_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_PSK_WITH_AES_256_CCM`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_PSK_WITH_AES_256_CCM_8`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_PSK_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_PSK_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_PSK_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_PSK_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_PSK_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_PSK_WITH_NULL_SHA256`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_PSK_WITH_NULL_SHA384`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_PSK_WITH_RC4_128_SHA`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5`: :zeek:type:`count`                             
:zeek:id:`SSL::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5`: :zeek:type:`count`                                 
:zeek:id:`SSL::TLS_RSA_EXPORT_WITH_RC4_40_MD5`: :zeek:type:`count`                                     
:zeek:id:`SSL::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_RSA_PSK_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_RSA_PSK_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                
:zeek:id:`SSL::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                           
:zeek:id:`SSL::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256`: :zeek:type:`count`                          
:zeek:id:`SSL::TLS_RSA_PSK_WITH_NULL_SHA256`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_PSK_WITH_NULL_SHA384`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_PSK_WITH_RC4_128_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_WITH_3DES_EDE_CBC_RMD`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_RSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                      
:zeek:id:`SSL::TLS_RSA_WITH_AES_128_CBC_RMD`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_WITH_AES_128_CBC_SHA256`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_RSA_WITH_AES_128_CCM`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_WITH_AES_128_CCM_8`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_RSA_WITH_AES_128_GCM_SHA256`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_RSA_WITH_AES_256_CBC_RMD`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                       
:zeek:id:`SSL::TLS_RSA_WITH_AES_256_CBC_SHA256`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_RSA_WITH_AES_256_CCM`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_WITH_AES_256_CCM_8`: :zeek:type:`count`                                         
:zeek:id:`SSL::TLS_RSA_WITH_AES_256_GCM_SHA384`: :zeek:type:`count`                                    
:zeek:id:`SSL::TLS_RSA_WITH_ARIA_128_CBC_SHA256`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_RSA_WITH_ARIA_128_GCM_SHA256`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_RSA_WITH_ARIA_256_CBC_SHA384`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_RSA_WITH_ARIA_256_GCM_SHA384`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_RSA_WITH_DES_CBC_SHA`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_WITH_IDEA_CBC_SHA`: :zeek:type:`count`                                          
:zeek:id:`SSL::TLS_RSA_WITH_NULL_MD5`: :zeek:type:`count`                                              
:zeek:id:`SSL::TLS_RSA_WITH_NULL_SHA`: :zeek:type:`count`                                              
:zeek:id:`SSL::TLS_RSA_WITH_NULL_SHA256`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_WITH_RC4_128_MD5`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_WITH_RC4_128_SHA`: :zeek:type:`count`                                           
:zeek:id:`SSL::TLS_RSA_WITH_SEED_CBC_SHA`: :zeek:type:`count`                                          
:zeek:id:`SSL::TLS_SHA256_SHA256`: :zeek:type:`count`                                                  
:zeek:id:`SSL::TLS_SHA384_SHA384`: :zeek:type:`count`                                                  
:zeek:id:`SSL::TLS_SM4_CCM_SM3`: :zeek:type:`count`                                                    
:zeek:id:`SSL::TLS_SM4_GCM_SM3`: :zeek:type:`count`                                                    
:zeek:id:`SSL::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                              
:zeek:id:`SSL::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                               
:zeek:id:`SSL::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA`: :zeek:type:`count`                                  
:zeek:id:`SSL::TLS_SRP_SHA_WITH_AES_128_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLS_SRP_SHA_WITH_AES_256_CBC_SHA`: :zeek:type:`count`                                   
:zeek:id:`SSL::TLSv10`: :zeek:type:`count`                                                             
:zeek:id:`SSL::TLSv11`: :zeek:type:`count`                                                             
:zeek:id:`SSL::TLSv12`: :zeek:type:`count`                                                             
:zeek:id:`SSL::TLSv13`: :zeek:type:`count`                                                             
:zeek:id:`SSL::V2_CLIENT_HELLO`: :zeek:type:`count`                                                    
:zeek:id:`SSL::V2_CLIENT_MASTER_KEY`: :zeek:type:`count`                                               
:zeek:id:`SSL::V2_ERROR`: :zeek:type:`count`                                                           
:zeek:id:`SSL::V2_SERVER_HELLO`: :zeek:type:`count`                                                    
:zeek:id:`SSL::alert_descriptions`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`   Mapping between numeric codes and human readable strings for alert
                                                                                                       descriptions.
:zeek:id:`SSL::alert_levels`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`         Mapping between numeric codes and human readable strings for alert
                                                                                                       levels.
:zeek:id:`SSL::cipher_desc`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`          This is a table of all known cipher specs.
:zeek:id:`SSL::ec_curves`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`            Mapping between numeric codes and human readable string for SSL/TLS elliptic curves.
:zeek:id:`SSL::ec_point_formats`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`     Mapping between numeric codes and human readable string for SSL/TLS EC point formats.
:zeek:id:`SSL::extensions`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`           Mapping between numeric codes and human readable strings for SSL/TLS
                                                                                                       extensions.
:zeek:id:`SSL::hash_algorithms`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`      Mapping between numeric codes and human readable strings for hash
                                                                                                       algorithms.
:zeek:id:`SSL::signature_algorithms`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` Mapping between numeric codes and human readable strings for signature
                                                                                                       algorithms.
:zeek:id:`SSL::version_strings`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function`      Mapping between the constants and string values for SSL/TLS versions.
====================================================================================================== =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: SSL::ALERT
   :source-code: base/protocols/ssl/consts.zeek 37 37

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::APPLICATION_DATA
   :source-code: base/protocols/ssl/consts.zeek 39 39

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::CERTIFICATE
   :source-code: base/protocols/ssl/consts.zeek 54 54

   :Type: :zeek:type:`count`
   :Default: ``11``


.. zeek:id:: SSL::CERTIFICATE_REQUEST
   :source-code: base/protocols/ssl/consts.zeek 56 56

   :Type: :zeek:type:`count`
   :Default: ``13``


.. zeek:id:: SSL::CERTIFICATE_STATUS
   :source-code: base/protocols/ssl/consts.zeek 62 62

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::CERTIFICATE_URL
   :source-code: base/protocols/ssl/consts.zeek 61 61

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::CERTIFICATE_VERIFY
   :source-code: base/protocols/ssl/consts.zeek 58 58

   :Type: :zeek:type:`count`
   :Default: ``15``


.. zeek:id:: SSL::CHANGE_CIPHER_SPEC
   :source-code: base/protocols/ssl/consts.zeek 36 36

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::CLIENT_HELLO
   :source-code: base/protocols/ssl/consts.zeek 48 48

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: SSL::CLIENT_KEY_EXCHANGE
   :source-code: base/protocols/ssl/consts.zeek 59 59

   :Type: :zeek:type:`count`
   :Default: ``16``


.. zeek:id:: SSL::DTLSv10
   :source-code: base/protocols/ssl/consts.zeek 11 11

   :Type: :zeek:type:`count`
   :Default: ``65279``


.. zeek:id:: SSL::DTLSv12
   :source-code: base/protocols/ssl/consts.zeek 13 13

   :Type: :zeek:type:`count`
   :Default: ``65277``


.. zeek:id:: SSL::DTLSv13
   :source-code: base/protocols/ssl/consts.zeek 14 14

   :Type: :zeek:type:`count`
   :Default: ``65276``


.. zeek:id:: SSL::ENCRYPTED_EXTENSIONS
   :source-code: base/protocols/ssl/consts.zeek 53 53

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: SSL::FINISHED
   :source-code: base/protocols/ssl/consts.zeek 60 60

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::HANDSHAKE
   :source-code: base/protocols/ssl/consts.zeek 38 38

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::HEARTBEAT
   :source-code: base/protocols/ssl/consts.zeek 40 40

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::HELLO_REQUEST
   :source-code: base/protocols/ssl/consts.zeek 47 47

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: SSL::HELLO_RETRY_REQUEST
   :source-code: base/protocols/ssl/consts.zeek 52 52

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: SSL::HELLO_VERIFY_REQUEST
   :source-code: base/protocols/ssl/consts.zeek 50 50

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: SSL::KEY_UPDATE
   :source-code: base/protocols/ssl/consts.zeek 64 64

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::SERVER_HELLO
   :source-code: base/protocols/ssl/consts.zeek 49 49

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::SERVER_HELLO_DONE
   :source-code: base/protocols/ssl/consts.zeek 57 57

   :Type: :zeek:type:`count`
   :Default: ``14``


.. zeek:id:: SSL::SERVER_KEY_EXCHANGE
   :source-code: base/protocols/ssl/consts.zeek 55 55

   :Type: :zeek:type:`count`
   :Default: ``12``


.. zeek:id:: SSL::SESSION_TICKET
   :source-code: base/protocols/ssl/consts.zeek 51 51

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: SSL::SSL_EXTENSION_APPLICATION_LAYER_PROTOCOL_NEGOTIATION
   :source-code: base/protocols/ssl/consts.zeek 163 163

   :Type: :zeek:type:`count`
   :Default: ``16``


.. zeek:id:: SSL::SSL_EXTENSION_APPLICATION_SETTING
   :source-code: base/protocols/ssl/consts.zeek 211 211

   :Type: :zeek:type:`count`
   :Default: ``17513``


.. zeek:id:: SSL::SSL_EXTENSION_CACHED_INFO
   :source-code: base/protocols/ssl/consts.zeek 172 172

   :Type: :zeek:type:`count`
   :Default: ``25``


.. zeek:id:: SSL::SSL_EXTENSION_CERTIFICATE_AUTHORITIES
   :source-code: base/protocols/ssl/consts.zeek 194 194

   :Type: :zeek:type:`count`
   :Default: ``47``


.. zeek:id:: SSL::SSL_EXTENSION_CERT_TYPE
   :source-code: base/protocols/ssl/consts.zeek 156 156

   :Type: :zeek:type:`count`
   :Default: ``9``


.. zeek:id:: SSL::SSL_EXTENSION_CHANNEL_ID
   :source-code: base/protocols/ssl/consts.zeek 212 212

   :Type: :zeek:type:`count`
   :Default: ``30031``


.. zeek:id:: SSL::SSL_EXTENSION_CHANNEL_ID_NEW
   :source-code: base/protocols/ssl/consts.zeek 213 213

   :Type: :zeek:type:`count`
   :Default: ``30032``


.. zeek:id:: SSL::SSL_EXTENSION_CLIENT_AUTHZ
   :source-code: base/protocols/ssl/consts.zeek 154 154

   :Type: :zeek:type:`count`
   :Default: ``7``


.. zeek:id:: SSL::SSL_EXTENSION_CLIENT_CERTIFICATE_TYPE
   :source-code: base/protocols/ssl/consts.zeek 166 166

   :Type: :zeek:type:`count`
   :Default: ``19``


.. zeek:id:: SSL::SSL_EXTENSION_CLIENT_CERTIFICATE_URL
   :source-code: base/protocols/ssl/consts.zeek 149 149

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::SSL_EXTENSION_COMPRESS_CERTIFICATE
   :source-code: base/protocols/ssl/consts.zeek 174 174

   :Type: :zeek:type:`count`
   :Default: ``27``


.. zeek:id:: SSL::SSL_EXTENSION_CONNECTION_ID
   :source-code: base/protocols/ssl/consts.zeek 201 201

   :Type: :zeek:type:`count`
   :Default: ``54``


.. zeek:id:: SSL::SSL_EXTENSION_CONNECTION_ID_DEPRECATED
   :source-code: base/protocols/ssl/consts.zeek 200 200

   :Type: :zeek:type:`count`
   :Default: ``53``


.. zeek:id:: SSL::SSL_EXTENSION_COOKIE
   :source-code: base/protocols/ssl/consts.zeek 191 191

   :Type: :zeek:type:`count`
   :Default: ``44``


.. zeek:id:: SSL::SSL_EXTENSION_DELEGATED_CREDENTIAL
   :source-code: base/protocols/ssl/consts.zeek 181 181

   :Type: :zeek:type:`count`
   :Default: ``34``


.. zeek:id:: SSL::SSL_EXTENSION_DNSSEC_CHAIN
   :source-code: base/protocols/ssl/consts.zeek 206 206

   :Type: :zeek:type:`count`
   :Default: ``59``


.. zeek:id:: SSL::SSL_EXTENSION_EARLY_DATA
   :source-code: base/protocols/ssl/consts.zeek 189 189

   :Type: :zeek:type:`count`
   :Default: ``42``


.. zeek:id:: SSL::SSL_EXTENSION_EC_POINT_FORMATS
   :source-code: base/protocols/ssl/consts.zeek 158 158

   :Type: :zeek:type:`count`
   :Default: ``11``


.. zeek:id:: SSL::SSL_EXTENSION_ENCRYPTED_CLIENT_CERTIFICATES
   :source-code: base/protocols/ssl/consts.zeek 210 210

   :Type: :zeek:type:`count`
   :Default: ``13180``


.. zeek:id:: SSL::SSL_EXTENSION_ENCRYPTED_CLIENT_HELLO
   :source-code: base/protocols/ssl/consts.zeek 215 215

   :Type: :zeek:type:`count`
   :Default: ``65037``


.. zeek:id:: SSL::SSL_EXTENSION_ENCRYPT_THEN_MAC
   :source-code: base/protocols/ssl/consts.zeek 169 169

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::SSL_EXTENSION_EXTENDED_MASTER_SECRET
   :source-code: base/protocols/ssl/consts.zeek 170 170

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::SSL_EXTENSION_EXTERNAL_ID_HASH
   :source-code: base/protocols/ssl/consts.zeek 202 202

   :Type: :zeek:type:`count`
   :Default: ``55``


.. zeek:id:: SSL::SSL_EXTENSION_EXTERNAL_SESSION_ID
   :source-code: base/protocols/ssl/consts.zeek 203 203

   :Type: :zeek:type:`count`
   :Default: ``56``


.. zeek:id:: SSL::SSL_EXTENSION_HEARTBEAT
   :source-code: base/protocols/ssl/consts.zeek 162 162

   :Type: :zeek:type:`count`
   :Default: ``15``


.. zeek:id:: SSL::SSL_EXTENSION_KEY_SHARE
   :source-code: base/protocols/ssl/consts.zeek 198 198

   :Type: :zeek:type:`count`
   :Default: ``51``


.. zeek:id:: SSL::SSL_EXTENSION_KEY_SHARE_OLD
   :source-code: base/protocols/ssl/consts.zeek 187 187

   :Type: :zeek:type:`count`
   :Default: ``40``


.. zeek:id:: SSL::SSL_EXTENSION_MAX_FRAGMENT_LENGTH
   :source-code: base/protocols/ssl/consts.zeek 148 148

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: SSL::SSL_EXTENSION_NEXT_PROTOCOL_NEGOTIATION
   :source-code: base/protocols/ssl/consts.zeek 208 208

   :Type: :zeek:type:`count`
   :Default: ``13172``


.. zeek:id:: SSL::SSL_EXTENSION_OID_FILTERS
   :source-code: base/protocols/ssl/consts.zeek 195 195

   :Type: :zeek:type:`count`
   :Default: ``48``


.. zeek:id:: SSL::SSL_EXTENSION_ORIGIN_BOUND_CERTIFICATES
   :source-code: base/protocols/ssl/consts.zeek 209 209

   :Type: :zeek:type:`count`
   :Default: ``13175``


.. zeek:id:: SSL::SSL_EXTENSION_PADDING
   :source-code: base/protocols/ssl/consts.zeek 168 168

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::SSL_EXTENSION_PADDING_TEMP
   :source-code: base/protocols/ssl/consts.zeek 214 214

   :Type: :zeek:type:`count`
   :Default: ``35655``


.. zeek:id:: SSL::SSL_EXTENSION_PASSWORD_SALT
   :source-code: base/protocols/ssl/consts.zeek 178 178

   :Type: :zeek:type:`count`
   :Default: ``31``


.. zeek:id:: SSL::SSL_EXTENSION_POST_HANDSHAKE_AUTH
   :source-code: base/protocols/ssl/consts.zeek 196 196

   :Type: :zeek:type:`count`
   :Default: ``49``


.. zeek:id:: SSL::SSL_EXTENSION_PRE_SHARED_KEY
   :source-code: base/protocols/ssl/consts.zeek 188 188

   :Type: :zeek:type:`count`
   :Default: ``41``


.. zeek:id:: SSL::SSL_EXTENSION_PSK_KEY_EXCHANGE_MODES
   :source-code: base/protocols/ssl/consts.zeek 192 192

   :Type: :zeek:type:`count`
   :Default: ``45``


.. zeek:id:: SSL::SSL_EXTENSION_PWD_CLEAR
   :source-code: base/protocols/ssl/consts.zeek 177 177

   :Type: :zeek:type:`count`
   :Default: ``30``


.. zeek:id:: SSL::SSL_EXTENSION_PWD_PROTECT
   :source-code: base/protocols/ssl/consts.zeek 176 176

   :Type: :zeek:type:`count`
   :Default: ``29``


.. zeek:id:: SSL::SSL_EXTENSION_QUIC_TRANSPORT_PARAMETERS
   :source-code: base/protocols/ssl/consts.zeek 204 204

   :Type: :zeek:type:`count`
   :Default: ``57``


.. zeek:id:: SSL::SSL_EXTENSION_RECORD_SIZE_LIMIT
   :source-code: base/protocols/ssl/consts.zeek 175 175

   :Type: :zeek:type:`count`
   :Default: ``28``


.. zeek:id:: SSL::SSL_EXTENSION_RENEGOTIATION_INFO
   :source-code: base/protocols/ssl/consts.zeek 216 216

   :Type: :zeek:type:`count`
   :Default: ``65281``


.. zeek:id:: SSL::SSL_EXTENSION_SEQUENCE_NUMBER_ENCRYPTION_ALGORITHMS
   :source-code: base/protocols/ssl/consts.zeek 207 207

   :Type: :zeek:type:`count`
   :Default: ``60``


.. zeek:id:: SSL::SSL_EXTENSION_SERVER_AUTHZ
   :source-code: base/protocols/ssl/consts.zeek 155 155

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: SSL::SSL_EXTENSION_SERVER_CERTIFICATE_TYPE
   :source-code: base/protocols/ssl/consts.zeek 167 167

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::SSL_EXTENSION_SERVER_NAME
   :source-code: base/protocols/ssl/consts.zeek 147 147

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: SSL::SSL_EXTENSION_SESSIONTICKET_TLS
   :source-code: base/protocols/ssl/consts.zeek 182 182

   :Type: :zeek:type:`count`
   :Default: ``35``


.. zeek:id:: SSL::SSL_EXTENSION_SIGNATURE_ALGORITHMS
   :source-code: base/protocols/ssl/consts.zeek 160 160

   :Type: :zeek:type:`count`
   :Default: ``13``


.. zeek:id:: SSL::SSL_EXTENSION_SIGNATURE_ALGORITHMS_CERT
   :source-code: base/protocols/ssl/consts.zeek 197 197

   :Type: :zeek:type:`count`
   :Default: ``50``


.. zeek:id:: SSL::SSL_EXTENSION_SIGNED_CERTIFICATE_TIMESTAMP
   :source-code: base/protocols/ssl/consts.zeek 165 165

   :Type: :zeek:type:`count`
   :Default: ``18``


.. zeek:id:: SSL::SSL_EXTENSION_SRP
   :source-code: base/protocols/ssl/consts.zeek 159 159

   :Type: :zeek:type:`count`
   :Default: ``12``


.. zeek:id:: SSL::SSL_EXTENSION_STATUS_REQUEST
   :source-code: base/protocols/ssl/consts.zeek 152 152

   :Type: :zeek:type:`count`
   :Default: ``5``


.. zeek:id:: SSL::SSL_EXTENSION_STATUS_REQUEST_V2
   :source-code: base/protocols/ssl/consts.zeek 164 164

   :Type: :zeek:type:`count`
   :Default: ``17``


.. zeek:id:: SSL::SSL_EXTENSION_SUPPORTED_EKT_CIPHERS
   :source-code: base/protocols/ssl/consts.zeek 186 186

   :Type: :zeek:type:`count`
   :Default: ``39``


.. zeek:id:: SSL::SSL_EXTENSION_SUPPORTED_GROUPS
   :source-code: base/protocols/ssl/consts.zeek 157 157

   :Type: :zeek:type:`count`
   :Default: ``10``


.. zeek:id:: SSL::SSL_EXTENSION_SUPPORTED_VERSIONS
   :source-code: base/protocols/ssl/consts.zeek 190 190

   :Type: :zeek:type:`count`
   :Default: ``43``


.. zeek:id:: SSL::SSL_EXTENSION_TICKETEARLYDATAINFO
   :source-code: base/protocols/ssl/consts.zeek 193 193

   :Type: :zeek:type:`count`
   :Default: ``46``


.. zeek:id:: SSL::SSL_EXTENSION_TICKET_PINNING
   :source-code: base/protocols/ssl/consts.zeek 179 179

   :Type: :zeek:type:`count`
   :Default: ``32``


.. zeek:id:: SSL::SSL_EXTENSION_TICKET_REQUEST
   :source-code: base/protocols/ssl/consts.zeek 205 205

   :Type: :zeek:type:`count`
   :Default: ``58``


.. zeek:id:: SSL::SSL_EXTENSION_TLMSP
   :source-code: base/protocols/ssl/consts.zeek 183 183

   :Type: :zeek:type:`count`
   :Default: ``36``


.. zeek:id:: SSL::SSL_EXTENSION_TLMSP_DELEGATE
   :source-code: base/protocols/ssl/consts.zeek 185 185

   :Type: :zeek:type:`count`
   :Default: ``38``


.. zeek:id:: SSL::SSL_EXTENSION_TLMSP_PROXYING
   :source-code: base/protocols/ssl/consts.zeek 184 184

   :Type: :zeek:type:`count`
   :Default: ``37``


.. zeek:id:: SSL::SSL_EXTENSION_TLS_CERT_WITH_EXTERN_PSK
   :source-code: base/protocols/ssl/consts.zeek 180 180

   :Type: :zeek:type:`count`
   :Default: ``33``


.. zeek:id:: SSL::SSL_EXTENSION_TLS_LTS
   :source-code: base/protocols/ssl/consts.zeek 173 173

   :Type: :zeek:type:`count`
   :Default: ``26``


.. zeek:id:: SSL::SSL_EXTENSION_TOKEN_BINDING
   :source-code: base/protocols/ssl/consts.zeek 171 171

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::SSL_EXTENSION_TRANSPARENCY_INFO
   :source-code: base/protocols/ssl/consts.zeek 199 199

   :Type: :zeek:type:`count`
   :Default: ``52``


.. zeek:id:: SSL::SSL_EXTENSION_TRUNCATED_HMAC
   :source-code: base/protocols/ssl/consts.zeek 151 151

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: SSL::SSL_EXTENSION_TRUSTED_CA_KEYS
   :source-code: base/protocols/ssl/consts.zeek 150 150

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: SSL::SSL_EXTENSION_USER_MAPPING
   :source-code: base/protocols/ssl/consts.zeek 153 153

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: SSL::SSL_EXTENSION_USE_SRTP
   :source-code: base/protocols/ssl/consts.zeek 161 161

   :Type: :zeek:type:`count`
   :Default: ``14``


.. zeek:id:: SSL::SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 432 432

   :Type: :zeek:type:`count`
   :Default: ``29``


.. zeek:id:: SSL::SSL_FORTEZZA_KEA_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 431 431

   :Type: :zeek:type:`count`
   :Default: ``28``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 802 802

   :Type: :zeek:type:`count`
   :Default: ``65279``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2
   :source-code: base/protocols/ssl/consts.zeek 804 804

   :Type: :zeek:type:`count`
   :Default: ``65504``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 801 801

   :Type: :zeek:type:`count`
   :Default: ``65278``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_DES_CBC_SHA_2
   :source-code: base/protocols/ssl/consts.zeek 803 803

   :Type: :zeek:type:`count`
   :Default: ``65505``


.. zeek:id:: SSL::SSL_RSA_WITH_3DES_EDE_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 808 808

   :Type: :zeek:type:`count`
   :Default: ``65411``


.. zeek:id:: SSL::SSL_RSA_WITH_DES_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 807 807

   :Type: :zeek:type:`count`
   :Default: ``65410``


.. zeek:id:: SSL::SSL_RSA_WITH_IDEA_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 806 806

   :Type: :zeek:type:`count`
   :Default: ``65409``


.. zeek:id:: SSL::SSL_RSA_WITH_RC2_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 805 805

   :Type: :zeek:type:`count`
   :Default: ``65408``


.. zeek:id:: SSL::SSLv2
   :source-code: base/protocols/ssl/consts.zeek 4 4

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 400 400

   :Type: :zeek:type:`count`
   :Default: ``458944``


.. zeek:id:: SSL::SSLv20_CK_DES_64_CBC_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 399 399

   :Type: :zeek:type:`count`
   :Default: ``393280``


.. zeek:id:: SSL::SSLv20_CK_IDEA_128_CBC_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 398 398

   :Type: :zeek:type:`count`
   :Default: ``327808``


.. zeek:id:: SSL::SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 397 397

   :Type: :zeek:type:`count`
   :Default: ``262272``


.. zeek:id:: SSL::SSLv20_CK_RC2_128_CBC_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 396 396

   :Type: :zeek:type:`count`
   :Default: ``196736``


.. zeek:id:: SSL::SSLv20_CK_RC4_128_EXPORT40_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 395 395

   :Type: :zeek:type:`count`
   :Default: ``131200``


.. zeek:id:: SSL::SSLv20_CK_RC4_128_WITH_MD5
   :source-code: base/protocols/ssl/consts.zeek 394 394

   :Type: :zeek:type:`count`
   :Default: ``65664``


.. zeek:id:: SSL::SSLv3
   :source-code: base/protocols/ssl/consts.zeek 5 5

   :Type: :zeek:type:`count`
   :Default: ``768``


.. zeek:id:: SSL::SUPPLEMENTAL_DATA
   :source-code: base/protocols/ssl/consts.zeek 63 63

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::TLS_AEGIS_128L_SHA256
   :source-code: base/protocols/ssl/consts.zeek 577 577

   :Type: :zeek:type:`count`
   :Default: ``4871``


.. zeek:id:: SSL::TLS_AEGIS_256_SHA384
   :source-code: base/protocols/ssl/consts.zeek 576 576

   :Type: :zeek:type:`count`
   :Default: ``4870``


.. zeek:id:: SSL::TLS_AES_128_CCM_8_SHA256
   :source-code: base/protocols/ssl/consts.zeek 574 574

   :Type: :zeek:type:`count`
   :Default: ``4869``


.. zeek:id:: SSL::TLS_AES_128_CCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 573 573

   :Type: :zeek:type:`count`
   :Default: ``4868``


.. zeek:id:: SSL::TLS_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 570 570

   :Type: :zeek:type:`count`
   :Default: ``4865``


.. zeek:id:: SSL::TLS_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 571 571

   :Type: :zeek:type:`count`
   :Default: ``4866``


.. zeek:id:: SSL::TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 582 582

   :Type: :zeek:type:`count`
   :Default: ``5818``


.. zeek:id:: SSL::TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 580 580

   :Type: :zeek:type:`count`
   :Default: ``5816``


.. zeek:id:: SSL::TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 581 581

   :Type: :zeek:type:`count`
   :Default: ``5817``


.. zeek:id:: SSL::TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 579 579

   :Type: :zeek:type:`count`
   :Default: ``5815``


.. zeek:id:: SSL::TLS_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 572 572

   :Type: :zeek:type:`count`
   :Default: ``4867``


.. zeek:id:: SSL::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 474 474

   :Type: :zeek:type:`count`
   :Default: ``99``


.. zeek:id:: SSL::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA
   :source-code: base/protocols/ssl/consts.zeek 476 476

   :Type: :zeek:type:`count`
   :Default: ``101``


.. zeek:id:: SSL::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 420 420

   :Type: :zeek:type:`count`
   :Default: ``17``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 486 486

   :Type: :zeek:type:`count`
   :Default: ``114``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 422 422

   :Type: :zeek:type:`count`
   :Default: ``19``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 487 487

   :Type: :zeek:type:`count`
   :Default: ``115``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 450 450

   :Type: :zeek:type:`count`
   :Default: ``50``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 464 464

   :Type: :zeek:type:`count`
   :Default: ``64``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 530 530

   :Type: :zeek:type:`count`
   :Default: ``162``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 488 488

   :Type: :zeek:type:`count`
   :Default: ``116``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 456 456

   :Type: :zeek:type:`count`
   :Default: ``56``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 481 481

   :Type: :zeek:type:`count`
   :Default: ``106``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 531 531

   :Type: :zeek:type:`count`
   :Default: ``163``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 652 652

   :Type: :zeek:type:`count`
   :Default: ``49218``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 672 672

   :Type: :zeek:type:`count`
   :Default: ``49238``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 653 653

   :Type: :zeek:type:`count`
   :Default: ``49219``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 673 673

   :Type: :zeek:type:`count`
   :Default: ``49239``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 468 468

   :Type: :zeek:type:`count`
   :Default: ``68``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 557 557

   :Type: :zeek:type:`count`
   :Default: ``189``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 715 715

   :Type: :zeek:type:`count`
   :Default: ``49280``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 503 503

   :Type: :zeek:type:`count`
   :Default: ``135``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 563 563

   :Type: :zeek:type:`count`
   :Default: ``195``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 716 716

   :Type: :zeek:type:`count`
   :Default: ``49281``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 421 421

   :Type: :zeek:type:`count`
   :Default: ``18``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 477 477

   :Type: :zeek:type:`count`
   :Default: ``102``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_SEED_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 521 521

   :Type: :zeek:type:`count`
   :Default: ``153``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 511 511

   :Type: :zeek:type:`count`
   :Default: ``143``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 512 512

   :Type: :zeek:type:`count`
   :Default: ``144``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 546 546

   :Type: :zeek:type:`count`
   :Default: ``178``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_CCM
   :source-code: base/protocols/ssl/consts.zeek 754 754

   :Type: :zeek:type:`count`
   :Default: ``49318``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 538 538

   :Type: :zeek:type:`count`
   :Default: ``170``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 513 513

   :Type: :zeek:type:`count`
   :Default: ``145``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 547 547

   :Type: :zeek:type:`count`
   :Default: ``179``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_CCM
   :source-code: base/protocols/ssl/consts.zeek 755 755

   :Type: :zeek:type:`count`
   :Default: ``49319``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 539 539

   :Type: :zeek:type:`count`
   :Default: ``171``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 688 688

   :Type: :zeek:type:`count`
   :Default: ``49254``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 694 694

   :Type: :zeek:type:`count`
   :Default: ``49260``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 689 689

   :Type: :zeek:type:`count`
   :Default: ``49255``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 695 695

   :Type: :zeek:type:`count`
   :Default: ``49261``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 737 737

   :Type: :zeek:type:`count`
   :Default: ``49302``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 731 731

   :Type: :zeek:type:`count`
   :Default: ``49296``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 738 738

   :Type: :zeek:type:`count`
   :Default: ``49303``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 732 732

   :Type: :zeek:type:`count`
   :Default: ``49297``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 791 791

   :Type: :zeek:type:`count`
   :Default: ``52397``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_NULL_SHA256
   :source-code: base/protocols/ssl/consts.zeek 548 548

   :Type: :zeek:type:`count`
   :Default: ``180``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_NULL_SHA384
   :source-code: base/protocols/ssl/consts.zeek 549 549

   :Type: :zeek:type:`count`
   :Default: ``181``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 510 510

   :Type: :zeek:type:`count`
   :Default: ``142``


.. zeek:id:: SSL::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 423 423

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 489 489

   :Type: :zeek:type:`count`
   :Default: ``119``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 425 425

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 490 490

   :Type: :zeek:type:`count`
   :Default: ``120``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 451 451

   :Type: :zeek:type:`count`
   :Default: ``51``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 478 478

   :Type: :zeek:type:`count`
   :Default: ``103``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CCM
   :source-code: base/protocols/ssl/consts.zeek 746 746

   :Type: :zeek:type:`count`
   :Default: ``49310``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 750 750

   :Type: :zeek:type:`count`
   :Default: ``49314``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 526 526

   :Type: :zeek:type:`count`
   :Default: ``158``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 491 491

   :Type: :zeek:type:`count`
   :Default: ``121``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 457 457

   :Type: :zeek:type:`count`
   :Default: ``57``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 482 482

   :Type: :zeek:type:`count`
   :Default: ``107``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CCM
   :source-code: base/protocols/ssl/consts.zeek 747 747

   :Type: :zeek:type:`count`
   :Default: ``49311``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 751 751

   :Type: :zeek:type:`count`
   :Default: ``49315``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 527 527

   :Type: :zeek:type:`count`
   :Default: ``159``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 654 654

   :Type: :zeek:type:`count`
   :Default: ``49220``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 668 668

   :Type: :zeek:type:`count`
   :Default: ``49234``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 655 655

   :Type: :zeek:type:`count`
   :Default: ``49221``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 669 669

   :Type: :zeek:type:`count`
   :Default: ``49235``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 469 469

   :Type: :zeek:type:`count`
   :Default: ``69``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 558 558

   :Type: :zeek:type:`count`
   :Default: ``190``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 711 711

   :Type: :zeek:type:`count`
   :Default: ``49276``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 504 504

   :Type: :zeek:type:`count`
   :Default: ``136``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 564 564

   :Type: :zeek:type:`count`
   :Default: ``196``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 712 712

   :Type: :zeek:type:`count`
   :Default: ``49277``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 788 788

   :Type: :zeek:type:`count`
   :Default: ``52394``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD
   :source-code: base/protocols/ssl/consts.zeek 784 784

   :Type: :zeek:type:`count`
   :Default: ``52245``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 424 424

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_SEED_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 522 522

   :Type: :zeek:type:`count`
   :Default: ``154``


.. zeek:id:: SSL::TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 428 428

   :Type: :zeek:type:`count`
   :Default: ``25``


.. zeek:id:: SSL::TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5
   :source-code: base/protocols/ssl/consts.zeek 426 426

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 430 430

   :Type: :zeek:type:`count`
   :Default: ``27``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 452 452

   :Type: :zeek:type:`count`
   :Default: ``52``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 483 483

   :Type: :zeek:type:`count`
   :Default: ``108``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 534 534

   :Type: :zeek:type:`count`
   :Default: ``166``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 458 458

   :Type: :zeek:type:`count`
   :Default: ``58``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 484 484

   :Type: :zeek:type:`count`
   :Default: ``109``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 535 535

   :Type: :zeek:type:`count`
   :Default: ``167``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 656 656

   :Type: :zeek:type:`count`
   :Default: ``49222``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 676 676

   :Type: :zeek:type:`count`
   :Default: ``49242``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 657 657

   :Type: :zeek:type:`count`
   :Default: ``49223``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 677 677

   :Type: :zeek:type:`count`
   :Default: ``49243``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 470 470

   :Type: :zeek:type:`count`
   :Default: ``70``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 559 559

   :Type: :zeek:type:`count`
   :Default: ``191``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 719 719

   :Type: :zeek:type:`count`
   :Default: ``49284``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 505 505

   :Type: :zeek:type:`count`
   :Default: ``137``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 565 565

   :Type: :zeek:type:`count`
   :Default: ``197``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 720 720

   :Type: :zeek:type:`count`
   :Default: ``49285``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 429 429

   :Type: :zeek:type:`count`
   :Default: ``26``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_RC4_128_MD5
   :source-code: base/protocols/ssl/consts.zeek 427 427

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_SEED_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 523 523

   :Type: :zeek:type:`count`
   :Default: ``155``


.. zeek:id:: SSL::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 414 414

   :Type: :zeek:type:`count`
   :Default: ``11``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 416 416

   :Type: :zeek:type:`count`
   :Default: ``13``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 448 448

   :Type: :zeek:type:`count`
   :Default: ``48``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 462 462

   :Type: :zeek:type:`count`
   :Default: ``62``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 532 532

   :Type: :zeek:type:`count`
   :Default: ``164``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 454 454

   :Type: :zeek:type:`count`
   :Default: ``54``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 479 479

   :Type: :zeek:type:`count`
   :Default: ``104``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 533 533

   :Type: :zeek:type:`count`
   :Default: ``165``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 648 648

   :Type: :zeek:type:`count`
   :Default: ``49214``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 674 674

   :Type: :zeek:type:`count`
   :Default: ``49240``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 649 649

   :Type: :zeek:type:`count`
   :Default: ``49215``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 675 675

   :Type: :zeek:type:`count`
   :Default: ``49241``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 466 466

   :Type: :zeek:type:`count`
   :Default: ``66``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 555 555

   :Type: :zeek:type:`count`
   :Default: ``187``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 717 717

   :Type: :zeek:type:`count`
   :Default: ``49282``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 501 501

   :Type: :zeek:type:`count`
   :Default: ``133``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 561 561

   :Type: :zeek:type:`count`
   :Default: ``193``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 718 718

   :Type: :zeek:type:`count`
   :Default: ``49283``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 415 415

   :Type: :zeek:type:`count`
   :Default: ``12``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_SEED_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 519 519

   :Type: :zeek:type:`count`
   :Default: ``151``


.. zeek:id:: SSL::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 417 417

   :Type: :zeek:type:`count`
   :Default: ``14``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 419 419

   :Type: :zeek:type:`count`
   :Default: ``16``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 449 449

   :Type: :zeek:type:`count`
   :Default: ``49``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 463 463

   :Type: :zeek:type:`count`
   :Default: ``63``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 528 528

   :Type: :zeek:type:`count`
   :Default: ``160``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 455 455

   :Type: :zeek:type:`count`
   :Default: ``55``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 480 480

   :Type: :zeek:type:`count`
   :Default: ``105``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 529 529

   :Type: :zeek:type:`count`
   :Default: ``161``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 650 650

   :Type: :zeek:type:`count`
   :Default: ``49216``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 670 670

   :Type: :zeek:type:`count`
   :Default: ``49236``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 651 651

   :Type: :zeek:type:`count`
   :Default: ``49217``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 671 671

   :Type: :zeek:type:`count`
   :Default: ``49237``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 467 467

   :Type: :zeek:type:`count`
   :Default: ``67``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 556 556

   :Type: :zeek:type:`count`
   :Default: ``188``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 713 713

   :Type: :zeek:type:`count`
   :Default: ``49278``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 502 502

   :Type: :zeek:type:`count`
   :Default: ``134``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 562 562

   :Type: :zeek:type:`count`
   :Default: ``194``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 714 714

   :Type: :zeek:type:`count`
   :Default: ``49279``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 418 418

   :Type: :zeek:type:`count`
   :Default: ``15``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_SEED_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 520 520

   :Type: :zeek:type:`count`
   :Default: ``152``


.. zeek:id:: SSL::TLS_ECCPWD_WITH_AES_128_CCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 767 767

   :Type: :zeek:type:`count`
   :Default: ``49330``


.. zeek:id:: SSL::TLS_ECCPWD_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 765 765

   :Type: :zeek:type:`count`
   :Default: ``49328``


.. zeek:id:: SSL::TLS_ECCPWD_WITH_AES_256_CCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 768 768

   :Type: :zeek:type:`count`
   :Default: ``49331``


.. zeek:id:: SSL::TLS_ECCPWD_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 766 766

   :Type: :zeek:type:`count`
   :Default: ``49329``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 593 593

   :Type: :zeek:type:`count`
   :Default: ``49160``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 594 594

   :Type: :zeek:type:`count`
   :Default: ``49161``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 620 620

   :Type: :zeek:type:`count`
   :Default: ``49187``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CCM
   :source-code: base/protocols/ssl/consts.zeek 760 760

   :Type: :zeek:type:`count`
   :Default: ``49324``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 762 762

   :Type: :zeek:type:`count`
   :Default: ``49326``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 628 628

   :Type: :zeek:type:`count`
   :Default: ``49195``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 595 595

   :Type: :zeek:type:`count`
   :Default: ``49162``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 621 621

   :Type: :zeek:type:`count`
   :Default: ``49188``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CCM
   :source-code: base/protocols/ssl/consts.zeek 761 761

   :Type: :zeek:type:`count`
   :Default: ``49325``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 763 763

   :Type: :zeek:type:`count`
   :Default: ``49327``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 629 629

   :Type: :zeek:type:`count`
   :Default: ``49196``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 658 658

   :Type: :zeek:type:`count`
   :Default: ``49224``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 678 678

   :Type: :zeek:type:`count`
   :Default: ``49244``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 659 659

   :Type: :zeek:type:`count`
   :Default: ``49225``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 679 679

   :Type: :zeek:type:`count`
   :Default: ``49245``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 701 701

   :Type: :zeek:type:`count`
   :Default: ``49266``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 721 721

   :Type: :zeek:type:`count`
   :Default: ``49286``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 702 702

   :Type: :zeek:type:`count`
   :Default: ``49267``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 722 722

   :Type: :zeek:type:`count`
   :Default: ``49287``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 787 787

   :Type: :zeek:type:`count`
   :Default: ``52393``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD
   :source-code: base/protocols/ssl/consts.zeek 783 783

   :Type: :zeek:type:`count`
   :Default: ``52244``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 591 591

   :Type: :zeek:type:`count`
   :Default: ``49158``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 592 592

   :Type: :zeek:type:`count`
   :Default: ``49159``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 637 637

   :Type: :zeek:type:`count`
   :Default: ``49204``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 638 638

   :Type: :zeek:type:`count`
   :Default: ``49205``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 640 640

   :Type: :zeek:type:`count`
   :Default: ``49207``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256
   :source-code: base/protocols/ssl/consts.zeek 798 798

   :Type: :zeek:type:`count`
   :Default: ``53251``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 799 799

   :Type: :zeek:type:`count`
   :Default: ``53253``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256_OLD
   :source-code: base/protocols/ssl/consts.zeek 794 794

   :Type: :zeek:type:`count`
   :Default: ``53252``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 796 796

   :Type: :zeek:type:`count`
   :Default: ``53249``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 639 639

   :Type: :zeek:type:`count`
   :Default: ``49206``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 641 641

   :Type: :zeek:type:`count`
   :Default: ``49208``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 797 797

   :Type: :zeek:type:`count`
   :Default: ``53250``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 698 698

   :Type: :zeek:type:`count`
   :Default: ``49264``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 699 699

   :Type: :zeek:type:`count`
   :Default: ``49265``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 741 741

   :Type: :zeek:type:`count`
   :Default: ``49306``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 742 742

   :Type: :zeek:type:`count`
   :Default: ``49307``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 790 790

   :Type: :zeek:type:`count`
   :Default: ``52396``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 642 642

   :Type: :zeek:type:`count`
   :Default: ``49209``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_NULL_SHA256
   :source-code: base/protocols/ssl/consts.zeek 643 643

   :Type: :zeek:type:`count`
   :Default: ``49210``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_NULL_SHA384
   :source-code: base/protocols/ssl/consts.zeek 644 644

   :Type: :zeek:type:`count`
   :Default: ``49211``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 636 636

   :Type: :zeek:type:`count`
   :Default: ``49203``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 603 603

   :Type: :zeek:type:`count`
   :Default: ``49170``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 604 604

   :Type: :zeek:type:`count`
   :Default: ``49171``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 624 624

   :Type: :zeek:type:`count`
   :Default: ``49191``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 632 632

   :Type: :zeek:type:`count`
   :Default: ``49199``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 605 605

   :Type: :zeek:type:`count`
   :Default: ``49172``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 625 625

   :Type: :zeek:type:`count`
   :Default: ``49192``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 633 633

   :Type: :zeek:type:`count`
   :Default: ``49200``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 662 662

   :Type: :zeek:type:`count`
   :Default: ``49228``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 682 682

   :Type: :zeek:type:`count`
   :Default: ``49248``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 663 663

   :Type: :zeek:type:`count`
   :Default: ``49229``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 683 683

   :Type: :zeek:type:`count`
   :Default: ``49249``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 705 705

   :Type: :zeek:type:`count`
   :Default: ``49270``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 725 725

   :Type: :zeek:type:`count`
   :Default: ``49290``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 706 706

   :Type: :zeek:type:`count`
   :Default: ``49271``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 726 726

   :Type: :zeek:type:`count`
   :Default: ``49291``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 786 786

   :Type: :zeek:type:`count`
   :Default: ``52392``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD
   :source-code: base/protocols/ssl/consts.zeek 782 782

   :Type: :zeek:type:`count`
   :Default: ``52243``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 601 601

   :Type: :zeek:type:`count`
   :Default: ``49168``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 602 602

   :Type: :zeek:type:`count`
   :Default: ``49169``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 608 608

   :Type: :zeek:type:`count`
   :Default: ``49175``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 609 609

   :Type: :zeek:type:`count`
   :Default: ``49176``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 610 610

   :Type: :zeek:type:`count`
   :Default: ``49177``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 606 606

   :Type: :zeek:type:`count`
   :Default: ``49173``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 607 607

   :Type: :zeek:type:`count`
   :Default: ``49174``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 588 588

   :Type: :zeek:type:`count`
   :Default: ``49155``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 589 589

   :Type: :zeek:type:`count`
   :Default: ``49156``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 622 622

   :Type: :zeek:type:`count`
   :Default: ``49189``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 630 630

   :Type: :zeek:type:`count`
   :Default: ``49197``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 590 590

   :Type: :zeek:type:`count`
   :Default: ``49157``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 623 623

   :Type: :zeek:type:`count`
   :Default: ``49190``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 631 631

   :Type: :zeek:type:`count`
   :Default: ``49198``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 660 660

   :Type: :zeek:type:`count`
   :Default: ``49226``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 680 680

   :Type: :zeek:type:`count`
   :Default: ``49246``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 661 661

   :Type: :zeek:type:`count`
   :Default: ``49227``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 681 681

   :Type: :zeek:type:`count`
   :Default: ``49247``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 703 703

   :Type: :zeek:type:`count`
   :Default: ``49268``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 723 723

   :Type: :zeek:type:`count`
   :Default: ``49288``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 704 704

   :Type: :zeek:type:`count`
   :Default: ``49269``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 724 724

   :Type: :zeek:type:`count`
   :Default: ``49289``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 586 586

   :Type: :zeek:type:`count`
   :Default: ``49153``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 587 587

   :Type: :zeek:type:`count`
   :Default: ``49154``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 598 598

   :Type: :zeek:type:`count`
   :Default: ``49165``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 599 599

   :Type: :zeek:type:`count`
   :Default: ``49166``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 626 626

   :Type: :zeek:type:`count`
   :Default: ``49193``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 634 634

   :Type: :zeek:type:`count`
   :Default: ``49201``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 600 600

   :Type: :zeek:type:`count`
   :Default: ``49167``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 627 627

   :Type: :zeek:type:`count`
   :Default: ``49194``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 635 635

   :Type: :zeek:type:`count`
   :Default: ``49202``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 664 664

   :Type: :zeek:type:`count`
   :Default: ``49230``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 684 684

   :Type: :zeek:type:`count`
   :Default: ``49250``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 665 665

   :Type: :zeek:type:`count`
   :Default: ``49231``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 685 685

   :Type: :zeek:type:`count`
   :Default: ``49251``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 707 707

   :Type: :zeek:type:`count`
   :Default: ``49272``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 727 727

   :Type: :zeek:type:`count`
   :Default: ``49292``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 708 708

   :Type: :zeek:type:`count`
   :Default: ``49273``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 728 728

   :Type: :zeek:type:`count`
   :Default: ``49293``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 596 596

   :Type: :zeek:type:`count`
   :Default: ``49163``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 597 597

   :Type: :zeek:type:`count`
   :Default: ``49164``


.. zeek:id:: SSL::TLS_EMPTY_RENEGOTIATION_INFO_SCSV
   :source-code: base/protocols/ssl/consts.zeek 809 809

   :Type: :zeek:type:`count`
   :Default: ``255``


.. zeek:id:: SSL::TLS_FALLBACK_SCSV
   :source-code: base/protocols/ssl/consts.zeek 584 584

   :Type: :zeek:type:`count`
   :Default: ``22016``


.. zeek:id:: SSL::TLS_GOSTR341001_WITH_28147_CNT_IMIT
   :source-code: base/protocols/ssl/consts.zeek 497 497

   :Type: :zeek:type:`count`
   :Default: ``129``


.. zeek:id:: SSL::TLS_GOSTR341001_WITH_NULL_GOSTR3411
   :source-code: base/protocols/ssl/consts.zeek 499 499

   :Type: :zeek:type:`count`
   :Default: ``131``


.. zeek:id:: SSL::TLS_GOSTR341094_WITH_28147_CNT_IMIT
   :source-code: base/protocols/ssl/consts.zeek 496 496

   :Type: :zeek:type:`count`
   :Default: ``128``


.. zeek:id:: SSL::TLS_GOSTR341094_WITH_NULL_GOSTR3411
   :source-code: base/protocols/ssl/consts.zeek 498 498

   :Type: :zeek:type:`count`
   :Default: ``130``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_28147_CNT_IMIT
   :source-code: base/protocols/ssl/consts.zeek 775 775

   :Type: :zeek:type:`count`
   :Default: ``49410``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC
   :source-code: base/protocols/ssl/consts.zeek 773 773

   :Type: :zeek:type:`count`
   :Default: ``49408``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L
   :source-code: base/protocols/ssl/consts.zeek 777 777

   :Type: :zeek:type:`count`
   :Default: ``49411``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S
   :source-code: base/protocols/ssl/consts.zeek 779 779

   :Type: :zeek:type:`count`
   :Default: ``49413``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC
   :source-code: base/protocols/ssl/consts.zeek 774 774

   :Type: :zeek:type:`count`
   :Default: ``49409``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L
   :source-code: base/protocols/ssl/consts.zeek 778 778

   :Type: :zeek:type:`count`
   :Default: ``49412``


.. zeek:id:: SSL::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S
   :source-code: base/protocols/ssl/consts.zeek 780 780

   :Type: :zeek:type:`count`
   :Default: ``49414``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5
   :source-code: base/protocols/ssl/consts.zeek 444 444

   :Type: :zeek:type:`count`
   :Default: ``41``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA
   :source-code: base/protocols/ssl/consts.zeek 441 441

   :Type: :zeek:type:`count`
   :Default: ``38``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5
   :source-code: base/protocols/ssl/consts.zeek 445 445

   :Type: :zeek:type:`count`
   :Default: ``42``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA
   :source-code: base/protocols/ssl/consts.zeek 442 442

   :Type: :zeek:type:`count`
   :Default: ``39``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC4_40_MD5
   :source-code: base/protocols/ssl/consts.zeek 446 446

   :Type: :zeek:type:`count`
   :Default: ``43``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC4_40_SHA
   :source-code: base/protocols/ssl/consts.zeek 443 443

   :Type: :zeek:type:`count`
   :Default: ``40``


.. zeek:id:: SSL::TLS_KRB5_WITH_3DES_EDE_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 438 438

   :Type: :zeek:type:`count`
   :Default: ``35``


.. zeek:id:: SSL::TLS_KRB5_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 434 434

   :Type: :zeek:type:`count`
   :Default: ``31``


.. zeek:id:: SSL::TLS_KRB5_WITH_DES_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 437 437

   :Type: :zeek:type:`count`
   :Default: ``34``


.. zeek:id:: SSL::TLS_KRB5_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 433 433

   :Type: :zeek:type:`count`
   :Default: ``30``


.. zeek:id:: SSL::TLS_KRB5_WITH_IDEA_CBC_MD5
   :source-code: base/protocols/ssl/consts.zeek 440 440

   :Type: :zeek:type:`count`
   :Default: ``37``


.. zeek:id:: SSL::TLS_KRB5_WITH_IDEA_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 436 436

   :Type: :zeek:type:`count`
   :Default: ``33``


.. zeek:id:: SSL::TLS_KRB5_WITH_RC4_128_MD5
   :source-code: base/protocols/ssl/consts.zeek 439 439

   :Type: :zeek:type:`count`
   :Default: ``36``


.. zeek:id:: SSL::TLS_KRB5_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 435 435

   :Type: :zeek:type:`count`
   :Default: ``32``


.. zeek:id:: SSL::TLS_NULL_WITH_NULL_NULL
   :source-code: base/protocols/ssl/consts.zeek 403 403

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: SSL::TLS_PSK_DHE_WITH_AES_128_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 758 758

   :Type: :zeek:type:`count`
   :Default: ``49322``


.. zeek:id:: SSL::TLS_PSK_DHE_WITH_AES_256_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 759 759

   :Type: :zeek:type:`count`
   :Default: ``49323``


.. zeek:id:: SSL::TLS_PSK_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 507 507

   :Type: :zeek:type:`count`
   :Default: ``139``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 508 508

   :Type: :zeek:type:`count`
   :Default: ``140``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 542 542

   :Type: :zeek:type:`count`
   :Default: ``174``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CCM
   :source-code: base/protocols/ssl/consts.zeek 752 752

   :Type: :zeek:type:`count`
   :Default: ``49316``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 756 756

   :Type: :zeek:type:`count`
   :Default: ``49320``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 536 536

   :Type: :zeek:type:`count`
   :Default: ``168``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 509 509

   :Type: :zeek:type:`count`
   :Default: ``141``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 543 543

   :Type: :zeek:type:`count`
   :Default: ``175``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CCM
   :source-code: base/protocols/ssl/consts.zeek 753 753

   :Type: :zeek:type:`count`
   :Default: ``49317``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 757 757

   :Type: :zeek:type:`count`
   :Default: ``49321``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 537 537

   :Type: :zeek:type:`count`
   :Default: ``169``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 686 686

   :Type: :zeek:type:`count`
   :Default: ``49252``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 692 692

   :Type: :zeek:type:`count`
   :Default: ``49258``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 687 687

   :Type: :zeek:type:`count`
   :Default: ``49253``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 693 693

   :Type: :zeek:type:`count`
   :Default: ``49259``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 735 735

   :Type: :zeek:type:`count`
   :Default: ``49300``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 729 729

   :Type: :zeek:type:`count`
   :Default: ``49294``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 736 736

   :Type: :zeek:type:`count`
   :Default: ``49301``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 730 730

   :Type: :zeek:type:`count`
   :Default: ``49295``


.. zeek:id:: SSL::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 789 789

   :Type: :zeek:type:`count`
   :Default: ``52395``


.. zeek:id:: SSL::TLS_PSK_WITH_NULL_SHA256
   :source-code: base/protocols/ssl/consts.zeek 544 544

   :Type: :zeek:type:`count`
   :Default: ``176``


.. zeek:id:: SSL::TLS_PSK_WITH_NULL_SHA384
   :source-code: base/protocols/ssl/consts.zeek 545 545

   :Type: :zeek:type:`count`
   :Default: ``177``


.. zeek:id:: SSL::TLS_PSK_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 506 506

   :Type: :zeek:type:`count`
   :Default: ``138``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 473 473

   :Type: :zeek:type:`count`
   :Default: ``98``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5
   :source-code: base/protocols/ssl/consts.zeek 472 472

   :Type: :zeek:type:`count`
   :Default: ``97``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5
   :source-code: base/protocols/ssl/consts.zeek 471 471

   :Type: :zeek:type:`count`
   :Default: ``96``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA
   :source-code: base/protocols/ssl/consts.zeek 475 475

   :Type: :zeek:type:`count`
   :Default: ``100``


.. zeek:id:: SSL::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 411 411

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: SSL::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5
   :source-code: base/protocols/ssl/consts.zeek 409 409

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: SSL::TLS_RSA_EXPORT_WITH_RC4_40_MD5
   :source-code: base/protocols/ssl/consts.zeek 406 406

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 515 515

   :Type: :zeek:type:`count`
   :Default: ``147``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 516 516

   :Type: :zeek:type:`count`
   :Default: ``148``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 550 550

   :Type: :zeek:type:`count`
   :Default: ``182``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 540 540

   :Type: :zeek:type:`count`
   :Default: ``172``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 517 517

   :Type: :zeek:type:`count`
   :Default: ``149``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 551 551

   :Type: :zeek:type:`count`
   :Default: ``183``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 541 541

   :Type: :zeek:type:`count`
   :Default: ``173``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 690 690

   :Type: :zeek:type:`count`
   :Default: ``49256``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 696 696

   :Type: :zeek:type:`count`
   :Default: ``49262``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 691 691

   :Type: :zeek:type:`count`
   :Default: ``49257``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 697 697

   :Type: :zeek:type:`count`
   :Default: ``49263``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 739 739

   :Type: :zeek:type:`count`
   :Default: ``49304``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 733 733

   :Type: :zeek:type:`count`
   :Default: ``49298``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 740 740

   :Type: :zeek:type:`count`
   :Default: ``49305``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 734 734

   :Type: :zeek:type:`count`
   :Default: ``49299``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256
   :source-code: base/protocols/ssl/consts.zeek 792 792

   :Type: :zeek:type:`count`
   :Default: ``52398``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_NULL_SHA256
   :source-code: base/protocols/ssl/consts.zeek 552 552

   :Type: :zeek:type:`count`
   :Default: ``184``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_NULL_SHA384
   :source-code: base/protocols/ssl/consts.zeek 553 553

   :Type: :zeek:type:`count`
   :Default: ``185``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 514 514

   :Type: :zeek:type:`count`
   :Default: ``146``


.. zeek:id:: SSL::TLS_RSA_WITH_3DES_EDE_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 492 492

   :Type: :zeek:type:`count`
   :Default: ``124``


.. zeek:id:: SSL::TLS_RSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 413 413

   :Type: :zeek:type:`count`
   :Default: ``10``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 493 493

   :Type: :zeek:type:`count`
   :Default: ``125``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 447 447

   :Type: :zeek:type:`count`
   :Default: ``47``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 460 460

   :Type: :zeek:type:`count`
   :Default: ``60``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CCM
   :source-code: base/protocols/ssl/consts.zeek 744 744

   :Type: :zeek:type:`count`
   :Default: ``49308``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 748 748

   :Type: :zeek:type:`count`
   :Default: ``49312``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 524 524

   :Type: :zeek:type:`count`
   :Default: ``156``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CBC_RMD
   :source-code: base/protocols/ssl/consts.zeek 494 494

   :Type: :zeek:type:`count`
   :Default: ``126``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 453 453

   :Type: :zeek:type:`count`
   :Default: ``53``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 461 461

   :Type: :zeek:type:`count`
   :Default: ``61``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CCM
   :source-code: base/protocols/ssl/consts.zeek 745 745

   :Type: :zeek:type:`count`
   :Default: ``49309``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CCM_8
   :source-code: base/protocols/ssl/consts.zeek 749 749

   :Type: :zeek:type:`count`
   :Default: ``49313``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 525 525

   :Type: :zeek:type:`count`
   :Default: ``157``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 646 646

   :Type: :zeek:type:`count`
   :Default: ``49212``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 666 666

   :Type: :zeek:type:`count`
   :Default: ``49232``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_256_CBC_SHA384
   :source-code: base/protocols/ssl/consts.zeek 647 647

   :Type: :zeek:type:`count`
   :Default: ``49213``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 667 667

   :Type: :zeek:type:`count`
   :Default: ``49233``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 465 465

   :Type: :zeek:type:`count`
   :Default: ``65``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 554 554

   :Type: :zeek:type:`count`
   :Default: ``186``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256
   :source-code: base/protocols/ssl/consts.zeek 709 709

   :Type: :zeek:type:`count`
   :Default: ``49274``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 500 500

   :Type: :zeek:type:`count`
   :Default: ``132``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
   :source-code: base/protocols/ssl/consts.zeek 560 560

   :Type: :zeek:type:`count`
   :Default: ``192``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384
   :source-code: base/protocols/ssl/consts.zeek 710 710

   :Type: :zeek:type:`count`
   :Default: ``49275``


.. zeek:id:: SSL::TLS_RSA_WITH_DES_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 412 412

   :Type: :zeek:type:`count`
   :Default: ``9``


.. zeek:id:: SSL::TLS_RSA_WITH_IDEA_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 410 410

   :Type: :zeek:type:`count`
   :Default: ``7``


.. zeek:id:: SSL::TLS_RSA_WITH_NULL_MD5
   :source-code: base/protocols/ssl/consts.zeek 404 404

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: SSL::TLS_RSA_WITH_NULL_SHA
   :source-code: base/protocols/ssl/consts.zeek 405 405

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::TLS_RSA_WITH_NULL_SHA256
   :source-code: base/protocols/ssl/consts.zeek 459 459

   :Type: :zeek:type:`count`
   :Default: ``59``


.. zeek:id:: SSL::TLS_RSA_WITH_RC4_128_MD5
   :source-code: base/protocols/ssl/consts.zeek 407 407

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: SSL::TLS_RSA_WITH_RC4_128_SHA
   :source-code: base/protocols/ssl/consts.zeek 408 408

   :Type: :zeek:type:`count`
   :Default: ``5``


.. zeek:id:: SSL::TLS_RSA_WITH_SEED_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 518 518

   :Type: :zeek:type:`count`
   :Default: ``150``


.. zeek:id:: SSL::TLS_SHA256_SHA256
   :source-code: base/protocols/ssl/consts.zeek 770 770

   :Type: :zeek:type:`count`
   :Default: ``49332``


.. zeek:id:: SSL::TLS_SHA384_SHA384
   :source-code: base/protocols/ssl/consts.zeek 771 771

   :Type: :zeek:type:`count`
   :Default: ``49333``


.. zeek:id:: SSL::TLS_SM4_CCM_SM3
   :source-code: base/protocols/ssl/consts.zeek 568 568

   :Type: :zeek:type:`count`
   :Default: ``199``


.. zeek:id:: SSL::TLS_SM4_GCM_SM3
   :source-code: base/protocols/ssl/consts.zeek 567 567

   :Type: :zeek:type:`count`
   :Default: ``198``


.. zeek:id:: SSL::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 613 613

   :Type: :zeek:type:`count`
   :Default: ``49180``


.. zeek:id:: SSL::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 616 616

   :Type: :zeek:type:`count`
   :Default: ``49183``


.. zeek:id:: SSL::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 619 619

   :Type: :zeek:type:`count`
   :Default: ``49186``


.. zeek:id:: SSL::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 612 612

   :Type: :zeek:type:`count`
   :Default: ``49179``


.. zeek:id:: SSL::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 615 615

   :Type: :zeek:type:`count`
   :Default: ``49182``


.. zeek:id:: SSL::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 618 618

   :Type: :zeek:type:`count`
   :Default: ``49185``


.. zeek:id:: SSL::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 611 611

   :Type: :zeek:type:`count`
   :Default: ``49178``


.. zeek:id:: SSL::TLS_SRP_SHA_WITH_AES_128_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 614 614

   :Type: :zeek:type:`count`
   :Default: ``49181``


.. zeek:id:: SSL::TLS_SRP_SHA_WITH_AES_256_CBC_SHA
   :source-code: base/protocols/ssl/consts.zeek 617 617

   :Type: :zeek:type:`count`
   :Default: ``49184``


.. zeek:id:: SSL::TLSv10
   :source-code: base/protocols/ssl/consts.zeek 6 6

   :Type: :zeek:type:`count`
   :Default: ``769``


.. zeek:id:: SSL::TLSv11
   :source-code: base/protocols/ssl/consts.zeek 7 7

   :Type: :zeek:type:`count`
   :Default: ``770``


.. zeek:id:: SSL::TLSv12
   :source-code: base/protocols/ssl/consts.zeek 8 8

   :Type: :zeek:type:`count`
   :Default: ``771``


.. zeek:id:: SSL::TLSv13
   :source-code: base/protocols/ssl/consts.zeek 9 9

   :Type: :zeek:type:`count`
   :Default: ``772``


.. zeek:id:: SSL::V2_CLIENT_HELLO
   :source-code: base/protocols/ssl/consts.zeek 42 42

   :Type: :zeek:type:`count`
   :Default: ``301``


.. zeek:id:: SSL::V2_CLIENT_MASTER_KEY
   :source-code: base/protocols/ssl/consts.zeek 43 43

   :Type: :zeek:type:`count`
   :Default: ``302``


.. zeek:id:: SSL::V2_ERROR
   :source-code: base/protocols/ssl/consts.zeek 41 41

   :Type: :zeek:type:`count`
   :Default: ``300``


.. zeek:id:: SSL::V2_SERVER_HELLO
   :source-code: base/protocols/ssl/consts.zeek 44 44

   :Type: :zeek:type:`count`
   :Default: ``304``


.. zeek:id:: SSL::alert_descriptions
   :source-code: base/protocols/ssl/consts.zeek 107 107

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [40] = "handshake_failure",
            [45] = "certificate_expired",
            [20] = "bad_record_mac",
            [46] = "certificate_unknown",
            [30] = "decompression_failure",
            [71] = "insufficient_security",
            [10] = "unexpected_message",
            [21] = "decryption_failed",
            [41] = "no_certificate",
            [47] = "illegal_parameter",
            [70] = "protocol_version",
            [80] = "internal_error",
            [50] = "decode_error",
            [120] = "no_application_protocol",
            [111] = "certificate_unobtainable",
            [115] = "unknown_psk_identity",
            [121] = "ech_required",
            [48] = "unknown_ca",
            [90] = "user_canceled",
            [42] = "bad_certificate",
            [49] = "access_denied",
            [86] = "inappropriate_fallback",
            [116] = "certificate_required",
            [113] = "bad_certificate_status_response",
            [112] = "unrecognized_name",
            [60] = "export_restriction",
            [22] = "record_overflow",
            [100] = "no_renegotiation",
            [51] = "decrypt_error",
            [43] = "unsupported_certificate",
            [114] = "bad_certificate_hash_value",
            [0] = "close_notify",
            [110] = "unsupported_extension",
            [44] = "certificate_revoked"
         }


   Mapping between numeric codes and human readable strings for alert
   descriptions.

.. zeek:id:: SSL::alert_levels
   :source-code: base/protocols/ssl/consts.zeek 68 68

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "fatal",
            [1] = "warning"
         }


   Mapping between numeric codes and human readable strings for alert
   levels.

.. zeek:id:: SSL::cipher_desc
   :source-code: base/protocols/ssl/consts.zeek 814 814

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [49279] = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [53] = "TLS_RSA_WITH_AES_256_CBC_SHA",
            [49161] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            [198] = "TLS_SM4_GCM_SM3",
            [49284] = "TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256",
            [49278] = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [52394] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            [49330] = "TLS_ECCPWD_WITH_AES_128_CCM_SHA256",
            [5815] = "TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256",
            [49251] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
            [146] = "TLS_RSA_PSK_WITH_RC4_128_SHA",
            [1] = "TLS_RSA_WITH_NULL_MD5",
            [35] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
            [102] = "TLS_DHE_DSS_WITH_RC4_128_SHA",
            [52393] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            [47802] = "grease_0xBABA",
            [49410] = "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT",
            [14] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
            [49198] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
            [49239] = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
            [31] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
            [192] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            [49283] = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
            [49291] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49295] = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
            [56] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            [49268] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
            [49281] = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
            [49275] = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [22016] = "TLS_FALLBACK_SCSV",
            [70] = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA",
            [132] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
            [4865] = "TLS_AES_128_GCM_SHA256",
            [49252] = "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
            [49181] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
            [49205] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            [49307] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [161] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
            [56026] = "grease_0xDADA",
            [60] = "TLS_RSA_WITH_AES_128_CBC_SHA256",
            [37] = "TLS_KRB5_WITH_IDEA_CBC_MD5",
            [185] = "TLS_RSA_PSK_WITH_NULL_SHA384",
            [49331] = "TLS_ECCPWD_WITH_AES_256_CCM_SHA384",
            [65279] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
            [49236] = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
            [20] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            [49195] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            [164] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
            [187] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
            [49299] = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
            [156] = "TLS_RSA_WITH_AES_128_GCM_SHA256",
            [97] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
            [21] = "TLS_DHE_RSA_WITH_DES_CBC_SHA",
            [12] = "TLS_DH_DSS_WITH_DES_CBC_SHA",
            [49175] = "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA",
            [169] = "TLS_PSK_WITH_AES_256_GCM_SHA384",
            [155] = "TLS_DH_ANON_WITH_SEED_CBC_SHA",
            [49159] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
            [5817] = "TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384",
            [150] = "TLS_RSA_WITH_SEED_CBC_SHA",
            [131200] = "SSLv20_CK_RC4_128_EXPORT40_WITH_MD5",
            [25] = "TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA",
            [49256] = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
            [49324] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
            [49321] = "TLS_PSK_WITH_AES_256_CCM_8",
            [49311] = "TLS_DHE_RSA_WITH_AES_256_CCM",
            [57] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            [42] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
            [49193] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            [49207] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
            [65278] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
            [49333] = "TLS_SHA384_SHA384",
            [49261] = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
            [108] = "TLS_DH_ANON_WITH_AES_128_CBC_SHA256",
            [49309] = "TLS_RSA_WITH_AES_256_CCM",
            [40] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
            [141] = "TLS_PSK_WITH_AES_256_CBC_SHA",
            [49285] = "TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384",
            [49244] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
            [23] = "TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5",
            [49246] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
            [65] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
            [13] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
            [49206] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
            [101] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
            [19018] = "grease_0x4A4A",
            [49412] = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L",
            [152] = "TLS_DH_RSA_WITH_SEED_CBC_SHA",
            [120] = "TLS_DHE_RSA_WITH_AES_128_CBC_RMD",
            [51914] = "grease_0xCACA",
            [49172] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            [49202] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
            [49260] = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
            [35466] = "grease_0x8A8A",
            [49323] = "TLS_PSK_DHE_WITH_AES_256_CCM_8",
            [100] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
            [166] = "TLS_DH_ANON_WITH_AES_128_GCM_SHA256",
            [65411] = "SSL_RSA_WITH_3DES_EDE_CBC_MD5",
            [131] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
            [149] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
            [96] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
            [49242] = "TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256",
            [39] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
            [49243] = "TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384",
            [262272] = "SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
            [27242] = "grease_0x6A6A",
            [41] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
            [60138] = "grease_0xEAEA",
            [49223] = "TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384",
            [49192] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            [54] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
            [49264] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
            [49249] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
            [172] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
            [49222] = "TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256",
            [49267] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
            [49327] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
            [114] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD",
            [49230] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
            [34] = "TLS_KRB5_WITH_DES_CBC_MD5",
            [49191] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            [49292] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49302] = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [178] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
            [49216] = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
            [7] = "TLS_RSA_WITH_IDEA_CBC_SHA",
            [49194] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            [128] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
            [49269] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
            [49280] = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
            [47] = "TLS_RSA_WITH_AES_128_CBC_SHA",
            [393280] = "SSLv20_CK_DES_64_CBC_WITH_MD5",
            [49254] = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
            [49179] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
            [24] = "TLS_DH_ANON_WITH_RC4_128_MD5",
            [49301] = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [69] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
            [99] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
            [162] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            [126] = "TLS_RSA_WITH_AES_256_CBC_RMD",
            [104] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
            [61] = "TLS_RSA_WITH_AES_256_CBC_SHA256",
            [49409] = "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC",
            [49258] = "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
            [49188] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            [49240] = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
            [49199] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            [49282] = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
            [67] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
            [15] = "TLS_DH_RSA_WITH_DES_CBC_SHA",
            [49241] = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
            [64] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            [52397] = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [106] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            [49255] = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
            [168] = "TLS_PSK_WITH_AES_128_GCM_SHA256",
            [49272] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [179] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
            [49163] = "TLS_ECDH_RSA_WITH_NULL_SHA",
            [130] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
            [49308] = "TLS_RSA_WITH_AES_128_CCM",
            [4866] = "TLS_AES_256_GCM_SHA384",
            [191] = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256",
            [49211] = "TLS_ECDHE_PSK_WITH_NULL_SHA384",
            [49215] = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
            [142] = "TLS_DHE_PSK_WITH_RC4_128_SHA",
            [49209] = "TLS_ECDHE_PSK_WITH_NULL_SHA",
            [49203] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
            [65408] = "SSL_RSA_WITH_RC2_CBC_MD5",
            [16] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
            [165] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
            [49186] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
            [173] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
            [49298] = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
            [143] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
            [14906] = "grease_0x3A3A",
            [49270] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [125] = "TLS_RSA_WITH_AES_128_CBC_RMD",
            [49326] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
            [8] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            [49287] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
            [159] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            [32] = "TLS_KRB5_WITH_RC4_128_SHA",
            [138] = "TLS_PSK_WITH_RC4_128_SHA",
            [170] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
            [49160] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            [49155] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
            [49253] = "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
            [49310] = "TLS_DHE_RSA_WITH_AES_128_CCM",
            [49414] = "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S",
            [49320] = "TLS_PSK_WITH_AES_128_CCM_8",
            [49] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
            [49313] = "TLS_RSA_WITH_AES_256_CCM_8",
            [49238] = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
            [197] = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256",
            [49189] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            [49293] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49314] = "TLS_DHE_RSA_WITH_AES_128_CCM_8",
            [49154] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
            [49263] = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
            [49274] = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49208] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
            [49257] = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
            [49184] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
            [49232] = "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
            [153] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
            [49235] = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
            [28] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
            [43690] = "grease_0xAAAA",
            [49229] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
            [107] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            [52] = "TLS_DH_ANON_WITH_AES_128_CBC_SHA",
            [49266] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
            [199] = "TLS_SM4_CCM_SM3",
            [105] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
            [49231] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
            [49178] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
            [49306] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [188] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [196] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            [29] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
            [115] = "TLS_DHE_DSS_WITH_AES_128_CBC_RMD",
            [49411] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L",
            [176] = "TLS_PSK_WITH_NULL_SHA256",
            [133] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
            [53253] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
            [49214] = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
            [49413] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S",
            [49182] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
            [49226] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
            [6682] = "grease_0x1A1A",
            [116] = "TLS_DHE_DSS_WITH_AES_256_CBC_RMD",
            [158] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            [49217] = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
            [3] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            [4870] = "TLS_AEGIS_256_SHA384",
            [183] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
            [49204] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
            [49312] = "TLS_RSA_WITH_AES_128_CCM_8",
            [49157] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            [4867] = "TLS_CHACHA20_POLY1305_SHA256",
            [49262] = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
            [49213] = "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
            [66] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
            [174] = "TLS_PSK_WITH_AES_128_CBC_SHA256",
            [49200] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            [49164] = "TLS_ECDH_RSA_WITH_RC4_128_SHA",
            [49218] = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
            [2] = "TLS_RSA_WITH_NULL_SHA",
            [49153] = "TLS_ECDH_ECDSA_WITH_NULL_SHA",
            [49318] = "TLS_DHE_PSK_WITH_AES_128_CCM",
            [49290] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49166] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            [163] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            [49245] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
            [182] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
            [109] = "TLS_DH_ANON_WITH_AES_256_CBC_SHA256",
            [49332] = "TLS_SHA256_SHA256",
            [196736] = "SSLv20_CK_RC2_128_CBC_WITH_MD5",
            [49276] = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [18] = "TLS_DHE_DSS_WITH_DES_CBC_SHA",
            [157] = "TLS_RSA_WITH_AES_256_GCM_SHA384",
            [0] = "TLS_NULL_WITH_NULL_NULL",
            [137] = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA",
            [19] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            [49187] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            [52395] = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [52392] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            [49171] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            [49234] = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
            [65664] = "SSLv20_CK_RC4_128_WITH_MD5",
            [49196] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            [184] = "TLS_RSA_PSK_WITH_NULL_SHA256",
            [49322] = "TLS_PSK_DHE_WITH_AES_128_CCM_8",
            [255] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            [59] = "TLS_RSA_WITH_NULL_SHA256",
            [38] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
            [154] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
            [49286] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49265] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
            [98] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
            [4868] = "TLS_AES_128_CCM_SHA256",
            [43] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
            [49303] = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [10794] = "grease_0x2A2A",
            [49408] = "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC",
            [49317] = "TLS_PSK_WITH_AES_256_CCM",
            [49329] = "TLS_ECCPWD_WITH_AES_256_GCM_SHA384",
            [23130] = "grease_0x5A5A",
            [49197] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            [194] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            [151] = "TLS_DH_DSS_WITH_SEED_CBC_SHA",
            [6] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
            [145] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
            [49210] = "TLS_ECDHE_PSK_WITH_NULL_SHA256",
            [53250] = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
            [10] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            [148] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
            [49185] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
            [49233] = "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
            [50] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            [49316] = "TLS_PSK_WITH_AES_128_CCM",
            [49170] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            [48] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
            [52398] = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [49250] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
            [5] = "TLS_RSA_WITH_RC4_128_SHA",
            [49168] = "TLS_ECDHE_RSA_WITH_NULL_SHA",
            [53249] = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
            [49305] = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [49156] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            [49319] = "TLS_DHE_PSK_WITH_AES_256_CCM",
            [49328] = "TLS_ECCPWD_WITH_AES_128_GCM_SHA256",
            [9] = "TLS_RSA_WITH_DES_CBC_SHA",
            [68] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
            [53251] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
            [49228] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
            [180] = "TLS_DHE_PSK_WITH_NULL_SHA256",
            [4871] = "TLS_AEGIS_128L_SHA256",
            [17] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            [65505] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA_2",
            [119] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD",
            [52243] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
            [52244] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
            [186] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [49315] = "TLS_DHE_RSA_WITH_AES_256_CCM_8",
            [193] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
            [189] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
            [49225] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
            [135] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
            [140] = "TLS_PSK_WITH_AES_128_CBC_SHA",
            [129] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
            [49221] = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
            [49288] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49273] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
            [49271] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
            [49325] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
            [49201] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
            [175] = "TLS_PSK_WITH_AES_256_CBC_SHA384",
            [26] = "TLS_DH_ANON_WITH_DES_CBC_SHA",
            [181] = "TLS_DHE_PSK_WITH_NULL_SHA384",
            [49300] = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [147] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
            [49190] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            [49173] = "TLS_ECDH_ANON_WITH_NULL_SHA",
            [190] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [5818] = "TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384",
            [103] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            [51] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            [167] = "TLS_DH_ANON_WITH_AES_256_GCM_SHA384",
            [33] = "TLS_KRB5_WITH_IDEA_CBC_SHA",
            [171] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
            [30] = "TLS_KRB5_WITH_DES_CBC_SHA",
            [327808] = "SSLv20_CK_IDEA_128_CBC_WITH_MD5",
            [177] = "TLS_PSK_WITH_NULL_SHA384",
            [52245] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
            [55] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
            [458944] = "SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5",
            [49183] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
            [49289] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
            [4] = "TLS_RSA_WITH_RC4_128_MD5",
            [124] = "TLS_RSA_WITH_3DES_EDE_CBC_RMD",
            [49158] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            [5816] = "TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            [58] = "TLS_DH_ANON_WITH_AES_256_CBC_SHA",
            [134] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
            [49224] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
            [49174] = "TLS_ECDH_ANON_WITH_RC4_128_SHA",
            [49169] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            [49227] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
            [49212] = "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
            [63] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
            [49162] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            [52396] = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [49237] = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
            [11] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
            [39578] = "grease_0x9A9A",
            [49176] = "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA",
            [22] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            [2570] = "grease_0x0A0A",
            [64250] = "grease_0xFAFA",
            [144] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
            [136] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
            [49294] = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
            [65409] = "SSL_RSA_WITH_IDEA_CBC_MD5",
            [65504] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2",
            [36] = "TLS_KRB5_WITH_RC4_128_MD5",
            [49180] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
            [31354] = "grease_0x7A7A",
            [27] = "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA",
            [195] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
            [4869] = "TLS_AES_128_CCM_8_SHA256",
            [53252] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256_OLD",
            [49296] = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
            [49248] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
            [62] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
            [160] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
            [139] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
            [49259] = "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
            [49219] = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
            [49247] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
            [49297] = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
            [121] = "TLS_DHE_RSA_WITH_AES_256_CBC_RMD",
            [49165] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            [49277] = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49220] = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
            [49167] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            [49177] = "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
            [49304] = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [65410] = "SSL_RSA_WITH_DES_CBC_MD5"
         }


   This is a table of all known cipher specs.  It can be used for
   detecting unknown ciphers and for converting the cipher spec
   constants into a human readable format.

.. zeek:id:: SSL::ec_curves
   :source-code: base/protocols/ssl/consts.zeek 314 314

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "secp192r1",
            [20] = "secp224k1",
            [259] = "ffdhe6144",
            [33] = "brainpoolP512r1tls13",
            [39] = "GC512B",
            [30] = "x448",
            [15] = "secp160k1",
            [28] = "brainpoolP512r1",
            [43690] = "grease_0xAAAA",
            [9] = "sect283k1",
            [27242] = "grease_0x6A6A",
            [21] = "secp224r1",
            [4] = "sect193r1",
            [12] = "sect409r1",
            [41] = "curveSM2",
            [60138] = "grease_0xEAEA",
            [17] = "secp160r2",
            [25] = "secp521r1",
            [65281] = "arbitrary_explicit_prime_curves",
            [29] = "x25519",
            [16] = "secp160r1",
            [25497] = "X25519Kyber768Draft00",
            [38] = "GC512A",
            [1] = "sect163k1",
            [6682] = "grease_0x1A1A",
            [11] = "sect409k1",
            [39578] = "grease_0x9A9A",
            [35] = "GC256B",
            [22] = "secp256k1",
            [256] = "ffdhe2048",
            [2570] = "grease_0x0A0A",
            [257] = "ffdhe3072",
            [14906] = "grease_0x3A3A",
            [64250] = "grease_0xFAFA",
            [47802] = "grease_0xBABA",
            [10794] = "grease_0x2A2A",
            [3] = "sect163r2",
            [25498] = "SecP256r1Kyber768Draft00",
            [23130] = "grease_0x5A5A",
            [34] = "GC256A",
            [40] = "GC512C",
            [36] = "GC256C",
            [6] = "sect233k1",
            [14] = "sect571r1",
            [31354] = "grease_0x7A7A",
            [31] = "brainpoolP256r1tls13",
            [8] = "sect239k1",
            [23] = "secp256r1",
            [27] = "brainpoolP384r1",
            [260] = "ffdhe8192",
            [7] = "sect233r1",
            [10] = "sect283r1",
            [32] = "brainpoolP384r1tls13",
            [13] = "sect571k1",
            [26] = "brainpoolP256r1",
            [19018] = "grease_0x4A4A",
            [51914] = "grease_0xCACA",
            [2] = "sect163r1",
            [65282] = "arbitrary_explicit_char2_curves",
            [24] = "secp384r1",
            [35466] = "grease_0x8A8A",
            [258] = "ffdhe4096",
            [5] = "sect193r2",
            [56026] = "grease_0xDADA",
            [37] = "GC256D",
            [18] = "secp192k1"
         }


   Mapping between numeric codes and human readable string for SSL/TLS elliptic curves.

.. zeek:id:: SSL::ec_point_formats
   :source-code: base/protocols/ssl/consts.zeek 387 387

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [0] = "uncompressed",
            [2] = "ansiX962_compressed_char2",
            [1] = "ansiX962_compressed_prime"
         }


   Mapping between numeric codes and human readable string for SSL/TLS EC point formats.

.. zeek:id:: SSL::extensions
   :source-code: base/protocols/ssl/consts.zeek 222 222

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [19] = "client_certificate_type",
            [20] = "server_certificate_type",
            [33] = "tls_cert_with_extern_psk",
            [39] = "supported_ekt_ciphers",
            [30] = "pwd_clear",
            [46] = "TicketEarlyDataInfo",
            [15] = "heartbeat",
            [28] = "record_size_limit",
            [35655] = "padding",
            [43690] = "grease_0xAAAA",
            [9] = "cert_type",
            [53] = "connection_id_deprecated",
            [55] = "external_id_hash",
            [27242] = "grease_0x6A6A",
            [52] = "transparency_info",
            [21] = "padding",
            [4] = "truncated_hmac",
            [12] = "srp",
            [41] = "pre_shared_key",
            [13180] = "encrypted_client_certificates",
            [60138] = "grease_0xEAEA",
            [58] = "ticket_request",
            [17] = "status_request_v2",
            [13175] = "origin_bound_certificates",
            [30032] = "channel_id_new",
            [25] = "cached_info",
            [65281] = "renegotiation_info",
            [29] = "pwd_protect",
            [16] = "application_layer_protocol_negotiation",
            [59] = "dnssec_chain",
            [38] = "TLMSP_delegate",
            [54] = "connection_id",
            [42] = "early_data",
            [57] = "quic_transport_parameters",
            [1] = "max_fragment_length",
            [6682] = "grease_0x1A1A",
            [11] = "ec_point_formats",
            [39578] = "grease_0x9A9A",
            [35] = "SessionTicket TLS",
            [22] = "encrypt_then_mac",
            [2570] = "grease_0x0A0A",
            [43] = "supported_versions",
            [14906] = "grease_0x3A3A",
            [64250] = "grease_0xFAFA",
            [47802] = "grease_0xBABA",
            [10794] = "grease_0x2A2A",
            [3] = "trusted_ca_keys",
            [44] = "cookie",
            [23130] = "grease_0x5A5A",
            [17513] = "application_setting",
            [34] = "delegated_credential",
            [45] = "psk_key_exchange_modes",
            [40] = "key_share_old",
            [36] = "TLMSP",
            [14] = "use_srtp",
            [6] = "user_mapping",
            [31354] = "grease_0x7A7A",
            [31] = "password_salt",
            [23] = "extended_master_secret",
            [8] = "server_authz",
            [27] = "compress_certificate",
            [56] = "external_session_id",
            [13172] = "next_protocol_negotiation",
            [7] = "client_authz",
            [10] = "supported_groups",
            [32] = "ticket_pinning",
            [13] = "signature_algorithms",
            [26] = "tls_lts",
            [30031] = "channel_id",
            [19018] = "grease_0x4A4A",
            [47] = "certificate_authorities",
            [50] = "signature_algorithms_cert",
            [51914] = "grease_0xCACA",
            [2] = "client_certificate_url",
            [48] = "oid_filters",
            [24] = "token_binding",
            [35466] = "grease_0x8A8A",
            [49] = "post_handshake_auth",
            [5] = "status_request",
            [65037] = "encrypted_client_hello",
            [56026] = "grease_0xDADA",
            [60] = "sequence_number_encryption_algorithms",
            [51] = "key_share",
            [37] = "TLMSP_proxying",
            [18] = "signed_certificate_timestamp",
            [0] = "server_name"
         }


   Mapping between numeric codes and human readable strings for SSL/TLS
   extensions.

.. zeek:id:: SSL::hash_algorithms
   :source-code: base/protocols/ssl/consts.zeek 75 75

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "sha1",
            [8] = "Intrinsic",
            [5] = "sha384",
            [3] = "sha224",
            [0] = "none",
            [6] = "sha512",
            [4] = "sha256",
            [1] = "md5"
         }


   Mapping between numeric codes and human readable strings for hash
   algorithms.

.. zeek:id:: SSL::signature_algorithms
   :source-code: base/protocols/ssl/consts.zeek 88 88

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [2] = "dsa",
            [11] = "rsa_pss_sha512",
            [5] = "rsa_pss_sha384",
            [7] = "ed25519",
            [10] = "rsa_pss_sha384",
            [6] = "rsa_pss_sha512",
            [4] = "rsa_pss_sha256",
            [65] = "gostr34102012_256",
            [64] = "gostr34102012_256",
            [8] = "ed448",
            [3] = "ecdsa",
            [0] = "anonymous",
            [9] = "rsa_pss_sha256",
            [1] = "rsa"
         }


   Mapping between numeric codes and human readable strings for signature
   algorithms.

.. zeek:id:: SSL::version_strings
   :source-code: base/protocols/ssl/consts.zeek 17 17

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function`
   :Default:

      ::

         {
            [769] = "TLSv10",
            [65279] = "DTLSv10",
            [768] = "SSLv3",
            [770] = "TLSv11",
            [772] = "TLSv13",
            [2] = "SSLv2",
            [65276] = "DTLSv13",
            [771] = "TLSv12",
            [65277] = "DTLSv12"
         }


   Mapping between the constants and string values for SSL/TLS versions.


