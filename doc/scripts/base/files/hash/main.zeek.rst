:tocdepth: 3

base/files/hash/main.zeek
=========================
.. zeek:namespace:: FileHash


:Namespace: FileHash
:Imports: :doc:`base/frameworks/files </scripts/base/frameworks/files/index>`

Summary
~~~~~~~
Redefinitions
#############
================================================================= ======================================================================
:zeek:type:`Files::Info`: :zeek:type:`record` :zeek:attr:`&redef` 
                                                                  
                                                                  :New Fields: :zeek:type:`Files::Info`
                                                                  
                                                                    md5: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                      An MD5 digest of the file contents.
                                                                  
                                                                    sha1: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                      A SHA1 digest of the file contents.
                                                                  
                                                                    sha256: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                      A SHA256 digest of the file contents.
================================================================= ======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

