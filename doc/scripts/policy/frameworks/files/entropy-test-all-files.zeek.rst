:tocdepth: 3

policy/frameworks/files/entropy-test-all-files.zeek
===================================================
.. zeek:namespace:: Files


:Namespace: Files

Summary
~~~~~~~
Redefinitions
#############
================================================================= =======================================================================
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                  
                                                                  :New Fields: :zeek:type:`Files::Info`
                                                                  
                                                                    entropy: :zeek:type:`double` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                      The information density of the contents of the file,
                                                                      expressed as a number of bits per character.
================================================================= =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

