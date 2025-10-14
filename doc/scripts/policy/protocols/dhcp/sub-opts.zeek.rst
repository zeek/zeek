:tocdepth: 3

policy/protocols/dhcp/sub-opts.zeek
===================================
.. zeek:namespace:: DHCP


:Namespace: DHCP
:Imports: :doc:`base/protocols/dhcp </scripts/base/protocols/dhcp/index>`

Summary
~~~~~~~
Redefinitions
#############
============================================ ===============================================================================
:zeek:type:`DHCP::Info`: :zeek:type:`record` 
                                             
                                             :New Fields: :zeek:type:`DHCP::Info`
                                             
                                               circuit_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 Added by DHCP relay agents which terminate switched or
                                                 permanent circuits.
                                             
                                               agent_remote_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 A globally unique identifier added by relay agents to identify
                                                 the remote host end of the circuit.
                                             
                                               subscriber_id: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                 The subscriber ID is a value independent of the physical
                                                 network configuration so that a customer's DHCP configuration
                                                 can be given to them correctly no matter where they are
                                                 physically connected.
============================================ ===============================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

