:tocdepth: 3

policy/protocols/ssh/md5-host-key-logging.zeek
==============================================
.. zeek:namespace:: SSH

Adds MD5 host_key field to ssh.log

:Namespace: SSH
:Imports: :doc:`base/protocols/ssh </scripts/base/protocols/ssh/index>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ========================================================================
:zeek:type:`SSH::Info`: :zeek:type:`record`

                                            :New Fields: :zeek:type:`SSH::Info`

                                              host_key: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                The server's key fingerprint
=========================================== ========================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

