:tocdepth: 3

policy/protocols/dhcp/software.zeek
===================================
.. zeek:namespace:: DHCP

Software identification and extraction for DHCP traffic.

:Namespace: DHCP
:Imports: :doc:`base/frameworks/software </scripts/base/frameworks/software/index>`, :doc:`base/protocols/dhcp </scripts/base/protocols/dhcp/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================== ===============================================================================
:zeek:type:`DHCP::Info`: :zeek:type:`record`   
                                               
                                               :New Fields: :zeek:type:`DHCP::Info`
                                               
                                                 client_software: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                   Software reported by the client in the `vendor_class` option.
                                               
                                                 server_software: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                   Software reported by the server in the `vendor_class` option.
:zeek:type:`Software::Type`: :zeek:type:`enum` 
                                               
                                               * :zeek:enum:`DHCP::CLIENT`:
                                                 Identifier for web browsers in the software framework.
                                               
                                               * :zeek:enum:`DHCP::SERVER`:
                                                 Identifier for web servers in the software framework.
============================================== ===============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

