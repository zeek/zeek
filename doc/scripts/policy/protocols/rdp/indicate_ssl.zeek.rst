:tocdepth: 3

policy/protocols/rdp/indicate_ssl.zeek
======================================
.. zeek:namespace:: RDP

If an RDP session is "upgraded" to SSL, this will be indicated
with this script in a new field added to the RDP log.

:Namespace: RDP
:Imports: :doc:`base/protocols/rdp </scripts/base/protocols/rdp/index>`, :doc:`base/protocols/ssl </scripts/base/protocols/ssl/index>`

Summary
~~~~~~~
Redefinitions
#############
=========================================== ===============================================================================================
:zeek:type:`RDP::Info`: :zeek:type:`record` 
                                            
                                            :New Fields: :zeek:type:`RDP::Info`
                                            
                                              ssl: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
                                                Flag the connection if it was seen over SSL.
=========================================== ===============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

