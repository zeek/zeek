:tocdepth: 3

policy/protocols/ssh/software.zeek
==================================
.. zeek:namespace:: SSH

Extracts SSH client and server information from SSH
connections and forwards it to the software framework.

:Namespace: SSH
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================== =======================================================
:zeek:type:`Software::Type`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`SSH::CLIENT`:
                                                 Identifier for SSH servers in the software framework.
                                               
                                               * :zeek:enum:`SSH::SERVER`:
                                                 Identifier for SSH clients in the software framework.
============================================== =======================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

