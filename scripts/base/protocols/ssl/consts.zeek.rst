:tocdepth: 3

base/protocols/ssl/consts.zeek
==============================
.. zeek:namespace:: SSL


:Namespace: SSL

Summary
~~~~~~~
Constants
#########
============================================================================================================================= =====================================================================================
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
:zeek:id:`SSL::alert_descriptions`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`   Mapping between numeric codes and human readable strings for alert
                                                                                                                              descriptions.
:zeek:id:`SSL::alert_levels`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`         Mapping between numeric codes and human readable strings for alert
                                                                                                                              levels.
:zeek:id:`SSL::cipher_desc`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`          This is a table of all known cipher specs.
:zeek:id:`SSL::ec_curves`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`            Mapping between numeric codes and human readable string for SSL/TLS elliptic curves.
:zeek:id:`SSL::ec_point_formats`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`     Mapping between numeric codes and human readable string for SSL/TLS EC point formats.
:zeek:id:`SSL::extensions`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`           Mapping between numeric codes and human readable strings for SSL/TLS
                                                                                                                              extensions.
:zeek:id:`SSL::hash_algorithms`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`      Mapping between numeric codes and human readable strings for hash
                                                                                                                              algorithms.
:zeek:id:`SSL::signature_algorithms`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional` Mapping between numeric codes and human readable strings for signature
                                                                                                                              algorithms.
:zeek:id:`SSL::version_strings`: :zeek:type:`table` :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`      Mapping between the constants and string values for SSL/TLS versions.
============================================================================================================================= =====================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Constants
#########
.. zeek:id:: SSL::ALERT

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::APPLICATION_DATA

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::CERTIFICATE

   :Type: :zeek:type:`count`
   :Default: ``11``


.. zeek:id:: SSL::CERTIFICATE_REQUEST

   :Type: :zeek:type:`count`
   :Default: ``13``


.. zeek:id:: SSL::CERTIFICATE_STATUS

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::CERTIFICATE_URL

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::CERTIFICATE_VERIFY

   :Type: :zeek:type:`count`
   :Default: ``15``


.. zeek:id:: SSL::CHANGE_CIPHER_SPEC

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::CLIENT_HELLO

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: SSL::CLIENT_KEY_EXCHANGE

   :Type: :zeek:type:`count`
   :Default: ``16``


.. zeek:id:: SSL::DTLSv10

   :Type: :zeek:type:`count`
   :Default: ``65279``


.. zeek:id:: SSL::DTLSv12

   :Type: :zeek:type:`count`
   :Default: ``65277``


.. zeek:id:: SSL::ENCRYPTED_EXTENSIONS

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: SSL::FINISHED

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::HANDSHAKE

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::HEARTBEAT

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::HELLO_REQUEST

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: SSL::HELLO_RETRY_REQUEST

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: SSL::HELLO_VERIFY_REQUEST

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: SSL::KEY_UPDATE

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::SERVER_HELLO

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::SERVER_HELLO_DONE

   :Type: :zeek:type:`count`
   :Default: ``14``


.. zeek:id:: SSL::SERVER_KEY_EXCHANGE

   :Type: :zeek:type:`count`
   :Default: ``12``


.. zeek:id:: SSL::SESSION_TICKET

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: SSL::SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``29``


.. zeek:id:: SSL::SSL_FORTEZZA_KEA_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``28``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``65279``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2

   :Type: :zeek:type:`count`
   :Default: ``65504``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``65278``


.. zeek:id:: SSL::SSL_RSA_FIPS_WITH_DES_CBC_SHA_2

   :Type: :zeek:type:`count`
   :Default: ``65505``


.. zeek:id:: SSL::SSL_RSA_WITH_3DES_EDE_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``65411``


.. zeek:id:: SSL::SSL_RSA_WITH_DES_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``65410``


.. zeek:id:: SSL::SSL_RSA_WITH_IDEA_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``65409``


.. zeek:id:: SSL::SSL_RSA_WITH_RC2_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``65408``


.. zeek:id:: SSL::SSLv2

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``458944``


.. zeek:id:: SSL::SSLv20_CK_DES_64_CBC_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``393280``


.. zeek:id:: SSL::SSLv20_CK_IDEA_128_CBC_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``327808``


.. zeek:id:: SSL::SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``262272``


.. zeek:id:: SSL::SSLv20_CK_RC2_128_CBC_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``196736``


.. zeek:id:: SSL::SSLv20_CK_RC4_128_EXPORT40_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``131200``


.. zeek:id:: SSL::SSLv20_CK_RC4_128_WITH_MD5

   :Type: :zeek:type:`count`
   :Default: ``65664``


.. zeek:id:: SSL::SSLv3

   :Type: :zeek:type:`count`
   :Default: ``768``


.. zeek:id:: SSL::SUPPLEMENTAL_DATA

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::TLS_AES_128_CCM_8_SHA256

   :Type: :zeek:type:`count`
   :Default: ``4869``


.. zeek:id:: SSL::TLS_AES_128_CCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``4868``


.. zeek:id:: SSL::TLS_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``4865``


.. zeek:id:: SSL::TLS_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``4866``


.. zeek:id:: SSL::TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``5818``


.. zeek:id:: SSL::TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``5816``


.. zeek:id:: SSL::TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``5817``


.. zeek:id:: SSL::TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``5815``


.. zeek:id:: SSL::TLS_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``4867``


.. zeek:id:: SSL::TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``99``


.. zeek:id:: SSL::TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA

   :Type: :zeek:type:`count`
   :Default: ``101``


.. zeek:id:: SSL::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``17``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``114``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``19``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``115``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``50``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``64``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``162``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``116``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``56``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``106``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``163``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49218``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49238``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49219``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49239``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``68``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``189``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49280``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``135``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``195``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49281``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``18``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``102``


.. zeek:id:: SSL::TLS_DHE_DSS_WITH_SEED_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``153``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``143``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``144``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``178``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_CCM

   :Type: :zeek:type:`count`
   :Default: ``49318``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``170``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``145``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``179``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_CCM

   :Type: :zeek:type:`count`
   :Default: ``49319``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``171``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49254``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49260``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49255``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49261``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49302``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49296``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49303``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49297``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52397``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_NULL_SHA256

   :Type: :zeek:type:`count`
   :Default: ``180``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_NULL_SHA384

   :Type: :zeek:type:`count`
   :Default: ``181``


.. zeek:id:: SSL::TLS_DHE_PSK_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``142``


.. zeek:id:: SSL::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``20``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``119``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``22``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``120``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``51``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``103``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CCM

   :Type: :zeek:type:`count`
   :Default: ``49310``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49314``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``158``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``121``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``57``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``107``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CCM

   :Type: :zeek:type:`count`
   :Default: ``49311``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49315``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``159``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49220``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49234``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49221``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49235``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``69``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``190``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49276``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``136``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``196``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49277``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52394``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD

   :Type: :zeek:type:`count`
   :Default: ``52245``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``21``


.. zeek:id:: SSL::TLS_DHE_RSA_WITH_SEED_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``154``


.. zeek:id:: SSL::TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``25``


.. zeek:id:: SSL::TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5

   :Type: :zeek:type:`count`
   :Default: ``23``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``27``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``52``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``108``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``166``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``58``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``109``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``167``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49222``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49242``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49223``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49243``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``70``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``191``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49284``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``137``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``197``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49285``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``26``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_RC4_128_MD5

   :Type: :zeek:type:`count`
   :Default: ``24``


.. zeek:id:: SSL::TLS_DH_ANON_WITH_SEED_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``155``


.. zeek:id:: SSL::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``11``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``13``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``48``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``62``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``164``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``54``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``104``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``165``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49214``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49240``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49215``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49241``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``66``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``187``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49282``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``133``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``193``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49283``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``12``


.. zeek:id:: SSL::TLS_DH_DSS_WITH_SEED_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``151``


.. zeek:id:: SSL::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``14``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``16``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``63``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``160``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``55``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``105``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``161``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49216``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49236``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49217``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49237``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``67``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``188``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49278``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``134``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``194``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49279``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``15``


.. zeek:id:: SSL::TLS_DH_RSA_WITH_SEED_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``152``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49160``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49161``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49187``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CCM

   :Type: :zeek:type:`count`
   :Default: ``49324``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49326``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49195``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49162``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49188``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CCM

   :Type: :zeek:type:`count`
   :Default: ``49325``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49327``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49196``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49224``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49244``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49225``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49245``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49266``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49286``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49267``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49287``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52393``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD

   :Type: :zeek:type:`count`
   :Default: ``52244``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``49158``


.. zeek:id:: SSL::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``49159``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49204``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49205``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49207``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256

   :Type: :zeek:type:`count`
   :Default: ``53251``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``53252``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``53249``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49206``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49208``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``53250``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49264``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49265``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49306``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49307``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52396``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``49209``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_NULL_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49210``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_NULL_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49211``


.. zeek:id:: SSL::TLS_ECDHE_PSK_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``49203``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49170``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49171``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49191``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49199``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49172``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49192``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49200``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49228``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49248``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49229``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49249``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49270``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49290``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49271``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49291``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52392``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD

   :Type: :zeek:type:`count`
   :Default: ``52243``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``49168``


.. zeek:id:: SSL::TLS_ECDHE_RSA_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``49169``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49175``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49176``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49177``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``49173``


.. zeek:id:: SSL::TLS_ECDH_ANON_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``49174``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49155``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49156``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49189``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49197``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49157``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49190``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49198``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49226``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49246``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49227``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49247``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49268``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49288``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49269``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49289``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``49153``


.. zeek:id:: SSL::TLS_ECDH_ECDSA_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``49154``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49165``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49166``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49193``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49201``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49167``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49194``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49202``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49230``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49250``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49231``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49251``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49272``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49292``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49273``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49293``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``49163``


.. zeek:id:: SSL::TLS_ECDH_RSA_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``49164``


.. zeek:id:: SSL::TLS_EMPTY_RENEGOTIATION_INFO_SCSV

   :Type: :zeek:type:`count`
   :Default: ``255``


.. zeek:id:: SSL::TLS_FALLBACK_SCSV

   :Type: :zeek:type:`count`
   :Default: ``22016``


.. zeek:id:: SSL::TLS_GOSTR341001_WITH_28147_CNT_IMIT

   :Type: :zeek:type:`count`
   :Default: ``129``


.. zeek:id:: SSL::TLS_GOSTR341001_WITH_NULL_GOSTR3411

   :Type: :zeek:type:`count`
   :Default: ``131``


.. zeek:id:: SSL::TLS_GOSTR341094_WITH_28147_CNT_IMIT

   :Type: :zeek:type:`count`
   :Default: ``128``


.. zeek:id:: SSL::TLS_GOSTR341094_WITH_NULL_GOSTR3411

   :Type: :zeek:type:`count`
   :Default: ``130``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5

   :Type: :zeek:type:`count`
   :Default: ``41``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA

   :Type: :zeek:type:`count`
   :Default: ``38``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5

   :Type: :zeek:type:`count`
   :Default: ``42``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA

   :Type: :zeek:type:`count`
   :Default: ``39``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC4_40_MD5

   :Type: :zeek:type:`count`
   :Default: ``43``


.. zeek:id:: SSL::TLS_KRB5_EXPORT_WITH_RC4_40_SHA

   :Type: :zeek:type:`count`
   :Default: ``40``


.. zeek:id:: SSL::TLS_KRB5_WITH_3DES_EDE_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``35``


.. zeek:id:: SSL::TLS_KRB5_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``31``


.. zeek:id:: SSL::TLS_KRB5_WITH_DES_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``34``


.. zeek:id:: SSL::TLS_KRB5_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``30``


.. zeek:id:: SSL::TLS_KRB5_WITH_IDEA_CBC_MD5

   :Type: :zeek:type:`count`
   :Default: ``37``


.. zeek:id:: SSL::TLS_KRB5_WITH_IDEA_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``33``


.. zeek:id:: SSL::TLS_KRB5_WITH_RC4_128_MD5

   :Type: :zeek:type:`count`
   :Default: ``36``


.. zeek:id:: SSL::TLS_KRB5_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``32``


.. zeek:id:: SSL::TLS_NULL_WITH_NULL_NULL

   :Type: :zeek:type:`count`
   :Default: ``0``


.. zeek:id:: SSL::TLS_PSK_DHE_WITH_AES_128_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49322``


.. zeek:id:: SSL::TLS_PSK_DHE_WITH_AES_256_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49323``


.. zeek:id:: SSL::TLS_PSK_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``139``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``140``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``174``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CCM

   :Type: :zeek:type:`count`
   :Default: ``49316``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49320``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``168``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``141``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``175``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CCM

   :Type: :zeek:type:`count`
   :Default: ``49317``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49321``


.. zeek:id:: SSL::TLS_PSK_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``169``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49252``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49258``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49253``


.. zeek:id:: SSL::TLS_PSK_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49259``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49300``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49294``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49301``


.. zeek:id:: SSL::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49295``


.. zeek:id:: SSL::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52395``


.. zeek:id:: SSL::TLS_PSK_WITH_NULL_SHA256

   :Type: :zeek:type:`count`
   :Default: ``176``


.. zeek:id:: SSL::TLS_PSK_WITH_NULL_SHA384

   :Type: :zeek:type:`count`
   :Default: ``177``


.. zeek:id:: SSL::TLS_PSK_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``138``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``98``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5

   :Type: :zeek:type:`count`
   :Default: ``97``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_RC4_56_MD5

   :Type: :zeek:type:`count`
   :Default: ``96``


.. zeek:id:: SSL::TLS_RSA_EXPORT1024_WITH_RC4_56_SHA

   :Type: :zeek:type:`count`
   :Default: ``100``


.. zeek:id:: SSL::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``8``


.. zeek:id:: SSL::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5

   :Type: :zeek:type:`count`
   :Default: ``6``


.. zeek:id:: SSL::TLS_RSA_EXPORT_WITH_RC4_40_MD5

   :Type: :zeek:type:`count`
   :Default: ``3``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``147``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``148``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``182``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``172``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``149``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``183``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``173``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49256``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49262``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49257``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49263``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49304``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49298``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49305``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49299``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256

   :Type: :zeek:type:`count`
   :Default: ``52398``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_NULL_SHA256

   :Type: :zeek:type:`count`
   :Default: ``184``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_NULL_SHA384

   :Type: :zeek:type:`count`
   :Default: ``185``


.. zeek:id:: SSL::TLS_RSA_PSK_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``146``


.. zeek:id:: SSL::TLS_RSA_WITH_3DES_EDE_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``124``


.. zeek:id:: SSL::TLS_RSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``10``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``125``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``47``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``60``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CCM

   :Type: :zeek:type:`count`
   :Default: ``49308``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49312``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``156``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CBC_RMD

   :Type: :zeek:type:`count`
   :Default: ``126``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``53``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``61``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CCM

   :Type: :zeek:type:`count`
   :Default: ``49309``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_CCM_8

   :Type: :zeek:type:`count`
   :Default: ``49313``


.. zeek:id:: SSL::TLS_RSA_WITH_AES_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``157``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49212``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49232``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_256_CBC_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49213``


.. zeek:id:: SSL::TLS_RSA_WITH_ARIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49233``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``65``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``186``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256

   :Type: :zeek:type:`count`
   :Default: ``49274``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``132``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256

   :Type: :zeek:type:`count`
   :Default: ``192``


.. zeek:id:: SSL::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384

   :Type: :zeek:type:`count`
   :Default: ``49275``


.. zeek:id:: SSL::TLS_RSA_WITH_DES_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``9``


.. zeek:id:: SSL::TLS_RSA_WITH_IDEA_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``7``


.. zeek:id:: SSL::TLS_RSA_WITH_NULL_MD5

   :Type: :zeek:type:`count`
   :Default: ``1``


.. zeek:id:: SSL::TLS_RSA_WITH_NULL_SHA

   :Type: :zeek:type:`count`
   :Default: ``2``


.. zeek:id:: SSL::TLS_RSA_WITH_NULL_SHA256

   :Type: :zeek:type:`count`
   :Default: ``59``


.. zeek:id:: SSL::TLS_RSA_WITH_RC4_128_MD5

   :Type: :zeek:type:`count`
   :Default: ``4``


.. zeek:id:: SSL::TLS_RSA_WITH_RC4_128_SHA

   :Type: :zeek:type:`count`
   :Default: ``5``


.. zeek:id:: SSL::TLS_RSA_WITH_SEED_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``150``


.. zeek:id:: SSL::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49180``


.. zeek:id:: SSL::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49183``


.. zeek:id:: SSL::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49186``


.. zeek:id:: SSL::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49179``


.. zeek:id:: SSL::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49182``


.. zeek:id:: SSL::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49185``


.. zeek:id:: SSL::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49178``


.. zeek:id:: SSL::TLS_SRP_SHA_WITH_AES_128_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49181``


.. zeek:id:: SSL::TLS_SRP_SHA_WITH_AES_256_CBC_SHA

   :Type: :zeek:type:`count`
   :Default: ``49184``


.. zeek:id:: SSL::TLSv10

   :Type: :zeek:type:`count`
   :Default: ``769``


.. zeek:id:: SSL::TLSv11

   :Type: :zeek:type:`count`
   :Default: ``770``


.. zeek:id:: SSL::TLSv12

   :Type: :zeek:type:`count`
   :Default: ``771``


.. zeek:id:: SSL::TLSv13

   :Type: :zeek:type:`count`
   :Default: ``772``


.. zeek:id:: SSL::V2_CLIENT_HELLO

   :Type: :zeek:type:`count`
   :Default: ``301``


.. zeek:id:: SSL::V2_CLIENT_MASTER_KEY

   :Type: :zeek:type:`count`
   :Default: ``302``


.. zeek:id:: SSL::V2_ERROR

   :Type: :zeek:type:`count`
   :Default: ``300``


.. zeek:id:: SSL::V2_SERVER_HELLO

   :Type: :zeek:type:`count`
   :Default: ``304``


.. zeek:id:: SSL::alert_descriptions

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [45] = "certificate_expired",
            [22] = "record_overflow",
            [30] = "decompression_failure",
            [44] = "certificate_revoked",
            [46] = "certificate_unknown",
            [86] = "inappropriate_fallback",
            [111] = "certificate_unobtainable",
            [114] = "bad_certificate_hash_value",
            [113] = "bad_certificate_status_response",
            [41] = "no_certificate",
            [43] = "unsupported_certificate",
            [51] = "decrypt_error",
            [80] = "internal_error",
            [100] = "no_renegotiation",
            [50] = "decode_error",
            [70] = "protocol_version",
            [120] = "no_application_protocol",
            [10] = "unexpected_message",
            [60] = "export_restriction",
            [110] = "unsupported_extension",
            [42] = "bad_certificate",
            [0] = "close_notify",
            [47] = "illegal_parameter",
            [115] = "unknown_psk_identity",
            [21] = "decryption_failed",
            [49] = "access_denied",
            [90] = "user_canceled",
            [20] = "bad_record_mac",
            [40] = "handshake_failure",
            [48] = "unknown_ca",
            [71] = "insufficient_security",
            [112] = "unrecognized_name"
         }


   Mapping between numeric codes and human readable strings for alert
   descriptions.

.. zeek:id:: SSL::alert_levels

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "fatal",
            [1] = "warning"
         }


   Mapping between numeric codes and human readable strings for alert
   levels.

.. zeek:id:: SSL::cipher_desc

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [4868] = "TLS_AES_128_CCM_SHA256",
            [49296] = "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
            [52394] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            [181] = "TLS_DHE_PSK_WITH_NULL_SHA384",
            [180] = "TLS_DHE_PSK_WITH_NULL_SHA256",
            [176] = "TLS_PSK_WITH_NULL_SHA256",
            [49240] = "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
            [49310] = "TLS_DHE_RSA_WITH_AES_128_CCM",
            [170] = "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
            [49300] = "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [26] = "TLS_DH_ANON_WITH_DES_CBC_SHA",
            [27] = "TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA",
            [49239] = "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
            [124] = "TLS_RSA_WITH_3DES_EDE_CBC_RMD",
            [49155] = "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
            [49308] = "TLS_RSA_WITH_AES_128_CCM",
            [4869] = "TLS_AES_128_CCM_8_SHA256",
            [52398] = "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [148] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
            [189] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
            [49192] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
            [102] = "TLS_DHE_DSS_WITH_RC4_128_SHA",
            [166] = "TLS_DH_ANON_WITH_AES_128_GCM_SHA256",
            [49261] = "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
            [69] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
            [9] = "TLS_RSA_WITH_DES_CBC_SHA",
            [64] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
            [49182] = "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
            [133] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
            [49293] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [65409] = "SSL_RSA_WITH_IDEA_CBC_MD5",
            [10] = "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            [1] = "TLS_RSA_WITH_NULL_MD5",
            [36] = "TLS_KRB5_WITH_RC4_128_MD5",
            [132] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
            [49183] = "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
            [98] = "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
            [149] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
            [23] = "TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5",
            [99] = "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
            [49185] = "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
            [48] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
            [327808] = "SSLv20_CK_IDEA_128_CBC_WITH_MD5",
            [143] = "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
            [33] = "TLS_KRB5_WITH_IDEA_CBC_SHA",
            [49241] = "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
            [49277] = "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49292] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [255] = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
            [49165] = "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
            [49228] = "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
            [169] = "TLS_PSK_WITH_AES_256_GCM_SHA384",
            [49236] = "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
            [49279] = "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49304] = "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [49202] = "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
            [49215] = "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
            [49305] = "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [49178] = "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
            [49179] = "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
            [49253] = "TLS_PSK_WITH_ARIA_256_CBC_SHA384",
            [49189] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
            [68] = "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
            [49260] = "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
            [101] = "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
            [65505] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA_2",
            [49186] = "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
            [49273] = "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
            [49198] = "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
            [49299] = "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
            [49301] = "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [49163] = "TLS_ECDH_RSA_WITH_NULL_SHA",
            [116] = "TLS_DHE_DSS_WITH_AES_256_CBC_RMD",
            [49175] = "TLS_ECDH_ANON_WITH_3DES_EDE_CBC_SHA",
            [49325] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
            [49211] = "TLS_ECDHE_PSK_WITH_NULL_SHA384",
            [134] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
            [49320] = "TLS_PSK_WITH_AES_128_CCM_8",
            [49255] = "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
            [52] = "TLS_DH_ANON_WITH_AES_128_CBC_SHA",
            [4] = "TLS_RSA_WITH_RC4_128_MD5",
            [17] = "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
            [25] = "TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA",
            [49158] = "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
            [5817] = "TLS_CECPQ1_RSA_WITH_AES_256_GCM_SHA384",
            [458944] = "SSLv20_CK_DES_192_EDE3_CBC_WITH_MD5",
            [49156] = "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
            [41] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
            [190] = "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [49259] = "TLS_PSK_WITH_ARIA_256_GCM_SHA384",
            [65408] = "SSL_RSA_WITH_RC2_CBC_MD5",
            [49208] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
            [49199] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            [49212] = "TLS_RSA_WITH_ARIA_128_CBC_SHA256",
            [37] = "TLS_KRB5_WITH_IDEA_CBC_MD5",
            [5] = "TLS_RSA_WITH_RC4_128_SHA",
            [49285] = "TLS_DH_ANON_WITH_CAMELLIA_256_GCM_SHA384",
            [103] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
            [49223] = "TLS_DH_ANON_WITH_ARIA_256_CBC_SHA384",
            [185] = "TLS_RSA_PSK_WITH_NULL_SHA384",
            [49276] = "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49281] = "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
            [126] = "TLS_RSA_WITH_AES_256_CBC_RMD",
            [49161] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
            [32] = "TLS_KRB5_WITH_RC4_128_SHA",
            [29] = "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
            [49247] = "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
            [52392] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            [70] = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA",
            [65504] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2",
            [109] = "TLS_DH_ANON_WITH_AES_256_CBC_SHA256",
            [130] = "TLS_GOSTR341094_WITH_NULL_GOSTR3411",
            [52243] = "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
            [178] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
            [49324] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
            [22] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
            [62] = "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
            [49224] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
            [49200] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            [179] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
            [49238] = "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
            [49286] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49159] = "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
            [49284] = "TLS_DH_ANON_WITH_CAMELLIA_128_GCM_SHA256",
            [49213] = "TLS_RSA_WITH_ARIA_256_CBC_SHA384",
            [152] = "TLS_DH_RSA_WITH_SEED_CBC_SHA",
            [194] = "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            [128] = "TLS_GOSTR341094_WITH_28147_CNT_IMIT",
            [49275] = "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [39] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
            [61] = "TLS_RSA_WITH_AES_256_CBC_SHA256",
            [38] = "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
            [49243] = "TLS_DH_ANON_WITH_ARIA_256_GCM_SHA384",
            [65664] = "SSLv20_CK_RC4_128_WITH_MD5",
            [3] = "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
            [107] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
            [49246] = "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
            [49217] = "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
            [66] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
            [49257] = "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
            [49258] = "TLS_PSK_WITH_ARIA_128_GCM_SHA256",
            [49154] = "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
            [51] = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
            [49194] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
            [192] = "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            [49171] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            [49302] = "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [49177] = "TLS_ECDH_ANON_WITH_AES_256_CBC_SHA",
            [121] = "TLS_DHE_RSA_WITH_AES_256_CBC_RMD",
            [14] = "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
            [49242] = "TLS_DH_ANON_WITH_ARIA_128_GCM_SHA256",
            [49168] = "TLS_ECDHE_RSA_WITH_NULL_SHA",
            [49153] = "TLS_ECDH_ECDSA_WITH_NULL_SHA",
            [138] = "TLS_PSK_WITH_RC4_128_SHA",
            [49157] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
            [49221] = "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
            [49263] = "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
            [165] = "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
            [173] = "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
            [49230] = "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
            [49314] = "TLS_DHE_RSA_WITH_AES_128_CCM_8",
            [172] = "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
            [53] = "TLS_RSA_WITH_AES_256_CBC_SHA",
            [49265] = "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
            [49282] = "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
            [52245] = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
            [139] = "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
            [49216] = "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
            [140] = "TLS_PSK_WITH_AES_128_CBC_SHA",
            [49272] = "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [53250] = "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
            [49287] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49290] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [53251] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
            [67] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
            [49254] = "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
            [52397] = "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [49226] = "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
            [49313] = "TLS_RSA_WITH_AES_256_CCM_8",
            [34] = "TLS_KRB5_WITH_DES_CBC_MD5",
            [154] = "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
            [5818] = "TLS_CECPQ1_ECDSA_WITH_AES_256_GCM_SHA384",
            [49294] = "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
            [49315] = "TLS_DHE_RSA_WITH_AES_256_CCM_8",
            [129] = "TLS_GOSTR341001_WITH_28147_CNT_IMIT",
            [55] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
            [49214] = "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
            [49220] = "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
            [159] = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
            [49166] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
            [49244] = "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
            [35] = "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
            [151] = "TLS_DH_DSS_WITH_SEED_CBC_SHA",
            [49181] = "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
            [58] = "TLS_DH_ANON_WITH_AES_256_CBC_SHA",
            [193] = "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
            [49291] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
            [49309] = "TLS_RSA_WITH_AES_256_CCM",
            [191] = "TLS_DH_ANON_WITH_CAMELLIA_128_CBC_SHA256",
            [31] = "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
            [65410] = "SSL_RSA_WITH_DES_CBC_MD5",
            [131200] = "SSLv20_CK_RC4_128_EXPORT40_WITH_MD5",
            [49266] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
            [49323] = "TLS_PSK_DHE_WITH_AES_256_CCM_8",
            [168] = "TLS_PSK_WITH_AES_128_GCM_SHA256",
            [7] = "TLS_RSA_WITH_IDEA_CBC_SHA",
            [13] = "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
            [150] = "TLS_RSA_WITH_SEED_CBC_SHA",
            [50] = "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
            [162] = "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
            [49229] = "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
            [49187] = "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
            [53249] = "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
            [65278] = "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
            [2] = "TLS_RSA_WITH_NULL_SHA",
            [104] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
            [60] = "TLS_RSA_WITH_AES_128_CBC_SHA256",
            [49209] = "TLS_ECDHE_PSK_WITH_NULL_SHA",
            [49218] = "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
            [18] = "TLS_DHE_DSS_WITH_DES_CBC_SHA",
            [43] = "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
            [52244] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD",
            [49191] = "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
            [49210] = "TLS_ECDHE_PSK_WITH_NULL_SHA256",
            [49234] = "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
            [49] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
            [49278] = "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [24] = "TLS_DH_ANON_WITH_RC4_128_MD5",
            [196] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
            [49233] = "TLS_RSA_WITH_ARIA_256_GCM_SHA384",
            [49237] = "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
            [49250] = "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
            [167] = "TLS_DH_ANON_WITH_AES_256_GCM_SHA384",
            [184] = "TLS_RSA_PSK_WITH_NULL_SHA256",
            [49303] = "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [49195] = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            [63] = "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
            [108] = "TLS_DH_ANON_WITH_AES_128_CBC_SHA256",
            [52395] = "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [4865] = "TLS_AES_128_GCM_SHA256",
            [5815] = "TLS_CECPQ1_RSA_WITH_CHACHA20_POLY1305_SHA256",
            [12] = "TLS_DH_DSS_WITH_DES_CBC_SHA",
            [49169] = "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
            [106] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
            [49184] = "TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
            [56] = "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
            [49251] = "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
            [196736] = "SSLv20_CK_RC2_128_CBC_WITH_MD5",
            [65] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
            [5816] = "TLS_CECPQ1_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            [49207] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
            [195] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
            [141] = "TLS_PSK_WITH_AES_256_CBC_SHA",
            [49317] = "TLS_PSK_WITH_AES_256_CCM",
            [53252] = "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
            [96] = "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
            [49271] = "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
            [171] = "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
            [49245] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
            [49256] = "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
            [49262] = "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
            [49316] = "TLS_PSK_WITH_AES_128_CCM",
            [174] = "TLS_PSK_WITH_AES_128_CBC_SHA256",
            [49270] = "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [136] = "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
            [65411] = "SSL_RSA_WITH_3DES_EDE_CBC_MD5",
            [49201] = "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
            [144] = "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
            [163] = "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
            [49298] = "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
            [49311] = "TLS_DHE_RSA_WITH_AES_256_CCM",
            [42] = "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
            [49225] = "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
            [120] = "TLS_DHE_RSA_WITH_AES_128_CBC_RMD",
            [262272] = "SSLv20_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
            [100] = "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
            [15] = "TLS_DH_RSA_WITH_DES_CBC_SHA",
            [49188] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
            [187] = "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
            [49206] = "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
            [135] = "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
            [21] = "TLS_DHE_RSA_WITH_DES_CBC_SHA",
            [16] = "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
            [49264] = "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
            [49321] = "TLS_PSK_WITH_AES_256_CCM_8",
            [52393] = "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            [49204] = "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
            [49167] = "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
            [49231] = "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
            [49295] = "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
            [11] = "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
            [54] = "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
            [47] = "TLS_RSA_WITH_AES_128_CBC_SHA",
            [49248] = "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
            [49269] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
            [49297] = "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
            [49174] = "TLS_ECDH_ANON_WITH_RC4_128_SHA",
            [155] = "TLS_DH_ANON_WITH_SEED_CBC_SHA",
            [49190] = "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
            [49274] = "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
            [49160] = "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
            [142] = "TLS_DHE_PSK_WITH_RC4_128_SHA",
            [137] = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA",
            [49227] = "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
            [49196] = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            [49172] = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
            [59] = "TLS_RSA_WITH_NULL_SHA256",
            [49235] = "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
            [6] = "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
            [175] = "TLS_PSK_WITH_AES_256_CBC_SHA384",
            [49252] = "TLS_PSK_WITH_ARIA_128_CBC_SHA256",
            [65279] = "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
            [4867] = "TLS_CHACHA20_POLY1305_SHA256",
            [49180] = "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
            [158] = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
            [115] = "TLS_DHE_DSS_WITH_AES_128_CBC_RMD",
            [114] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD",
            [49322] = "TLS_PSK_DHE_WITH_AES_128_CCM_8",
            [8] = "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
            [182] = "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
            [57] = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
            [49280] = "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
            [49326] = "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
            [49193] = "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
            [147] = "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
            [40] = "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
            [183] = "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
            [160] = "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
            [157] = "TLS_RSA_WITH_AES_256_GCM_SHA384",
            [49267] = "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
            [30] = "TLS_KRB5_WITH_DES_CBC_SHA",
            [49176] = "TLS_ECDH_ANON_WITH_AES_128_CBC_SHA",
            [119] = "TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD",
            [145] = "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
            [49205] = "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
            [52396] = "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
            [188] = "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [28] = "SSL_FORTEZZA_KEA_WITH_NULL_SHA",
            [49173] = "TLS_ECDH_ANON_WITH_NULL_SHA",
            [0] = "TLS_NULL_WITH_NULL_NULL",
            [49306] = "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
            [164] = "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
            [49203] = "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
            [49283] = "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
            [393280] = "SSLv20_CK_DES_64_CBC_WITH_MD5",
            [161] = "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
            [186] = "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
            [49289] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
            [131] = "TLS_GOSTR341001_WITH_NULL_GOSTR3411",
            [49162] = "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
            [49312] = "TLS_RSA_WITH_AES_128_CCM_8",
            [49197] = "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
            [20] = "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
            [177] = "TLS_PSK_WITH_NULL_SHA384",
            [49164] = "TLS_ECDH_RSA_WITH_RC4_128_SHA",
            [49319] = "TLS_DHE_PSK_WITH_AES_256_CCM",
            [105] = "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
            [153] = "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
            [49318] = "TLS_DHE_PSK_WITH_AES_128_CCM",
            [49170] = "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
            [146] = "TLS_RSA_PSK_WITH_RC4_128_SHA",
            [49249] = "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
            [125] = "TLS_RSA_WITH_AES_128_CBC_RMD",
            [49307] = "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
            [49327] = "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
            [49219] = "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
            [49222] = "TLS_DH_ANON_WITH_ARIA_128_CBC_SHA256",
            [19] = "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
            [49232] = "TLS_RSA_WITH_ARIA_128_GCM_SHA256",
            [22016] = "TLS_FALLBACK_SCSV",
            [49268] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
            [97] = "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
            [197] = "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA256",
            [156] = "TLS_RSA_WITH_AES_128_GCM_SHA256",
            [4866] = "TLS_AES_256_GCM_SHA384",
            [49288] = "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256"
         }


   This is a table of all known cipher specs.  It can be used for
   detecting unknown ciphers and for converting the cipher spec
   constants into a human readable format.

.. zeek:id:: SSL::ec_curves

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "sect163r1",
            [9] = "sect283k1",
            [17] = "secp160r2",
            [27] = "brainpoolP384r1",
            [6] = "sect233k1",
            [11] = "sect409k1",
            [14] = "sect571r1",
            [258] = "ffdhe4096",
            [4] = "sect193r1",
            [22] = "secp256k1",
            [24] = "secp384r1",
            [30] = "x448",
            [256] = "ffdhe2048",
            [1] = "sect163k1",
            [8] = "sect239k1",
            [7] = "sect233r1",
            [15] = "secp160k1",
            [257] = "ffdhe3072",
            [23] = "secp256r1",
            [29] = "x25519",
            [5] = "sect193r2",
            [25] = "secp521r1",
            [19] = "secp192r1",
            [28] = "brainpoolP512r1",
            [260] = "ffdhe8192",
            [10] = "sect283r1",
            [259] = "ffdhe6144",
            [65281] = "arbitrary_explicit_prime_curves",
            [3] = "sect163r2",
            [12] = "sect409r1",
            [13] = "sect571k1",
            [18] = "secp192k1",
            [21] = "secp224r1",
            [16] = "secp160r1",
            [20] = "secp224k1",
            [26] = "brainpoolP256r1",
            [65282] = "arbitrary_explicit_char2_curves"
         }


   Mapping between numeric codes and human readable string for SSL/TLS elliptic curves.

.. zeek:id:: SSL::ec_point_formats

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "ansiX962_compressed_char2",
            [1] = "ansiX962_compressed_prime",
            [0] = "uncompressed"
         }


   Mapping between numeric codes and human readable string for SSL/TLS EC point formats.

.. zeek:id:: SSL::extensions

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "client_certificate_url",
            [9] = "cert_type",
            [17] = "status_request_v2",
            [13172] = "next_protocol_negotiation",
            [6] = "user_mapping",
            [11] = "ec_point_formats",
            [14] = "use_srtp",
            [45] = "psk_key_exchange_modes",
            [30032] = "channel_id_new",
            [4] = "truncated_hmac",
            [22] = "encrypt_then_mac",
            [24] = "token_binding",
            [44] = "cookie",
            [46] = "TicketEarlyDataInfo",
            [1] = "max_fragment_length",
            [8] = "server_authz",
            [35655] = "padding",
            [7] = "client_authz",
            [15] = "heartbeat",
            [23] = "extended_master_secret",
            [41] = "pre_shared_key",
            [43] = "supported_versions",
            [5] = "status_request",
            [25] = "cached_info",
            [13175] = "origin_bound_certificates",
            [19] = "client_certificate_type",
            [10] = "supported_groups",
            [35] = "SessionTicket TLS",
            [42] = "early_data",
            [65281] = "renegotiation_info",
            [0] = "server_name",
            [47] = "certificate_authorities",
            [13180] = "encrypted_client_certificates",
            [3] = "trusted_ca_keys",
            [12] = "srp",
            [13] = "signature_algorithms",
            [18] = "signed_certificate_timestamp",
            [21] = "padding",
            [30031] = "channel_id",
            [16] = "application_layer_protocol_negotiation",
            [20] = "server_certificate_type",
            [40] = "key_share",
            [48] = "oid_filters"
         }


   Mapping between numeric codes and human readable strings for SSL/TLS
   extensions.

.. zeek:id:: SSL::hash_algorithms

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "sha1",
            [6] = "sha512",
            [4] = "sha256",
            [1] = "md5",
            [8] = "Intrinsic",
            [5] = "sha384",
            [0] = "none",
            [3] = "sha224"
         }


   Mapping between numeric codes and human readable strings for hash
   algorithms.

.. zeek:id:: SSL::signature_algorithms

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "dsa",
            [9] = "rsa_pss_sha256",
            [6] = "rsa_pss_sha512",
            [11] = "rsa_pss_sha512",
            [4] = "rsa_pss_sha256",
            [1] = "rsa",
            [8] = "ed448",
            [7] = "ed25519",
            [5] = "rsa_pss_sha384",
            [10] = "rsa_pss_sha384",
            [64] = "gostr34102012_256",
            [0] = "anonymous",
            [65] = "gostr34102012_256",
            [3] = "ecdsa"
         }


   Mapping between numeric codes and human readable strings for signature
   algorithms.

.. zeek:id:: SSL::version_strings

   :Type: :zeek:type:`table` [:zeek:type:`count`] of :zeek:type:`string`
   :Attributes: :zeek:attr:`&default` = :zeek:type:`function` :zeek:attr:`&optional`
   :Default:

      ::

         {
            [2] = "SSLv2",
            [65279] = "DTLSv10",
            [770] = "TLSv11",
            [769] = "TLSv10",
            [772] = "TLSv13",
            [65277] = "DTLSv12",
            [771] = "TLSv12",
            [768] = "SSLv3"
         }


   Mapping between the constants and string values for SSL/TLS versions.


