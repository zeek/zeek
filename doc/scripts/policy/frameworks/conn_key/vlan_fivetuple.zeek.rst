:tocdepth: 3

policy/frameworks/conn_key/vlan_fivetuple.zeek
==============================================

This script adapts Zeek's connection key to include 802.1Q VLAN and
Q-in-Q tags, when available. Zeek normally ignores VLAN tags for connection
lookups; this change makes it factor them in and also makes those VLAN tags
part of the :zeek:see:`conn_id` record.


Summary
~~~~~~~
Redefinitions
#############
========================================================================== =======================================================================
:zeek:id:`ConnKey::factory`: :zeek:type:`ConnKey::Tag` :zeek:attr:`&redef` 
:zeek:type:`conn_id_ctx`: :zeek:type:`record`                              
                                                                           
                                                                           :New Fields: :zeek:type:`conn_id_ctx`
                                                                           
                                                                             vlan: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                               The outer VLAN for this connection, if applicable.
                                                                           
                                                                             inner_vlan: :zeek:type:`int` :zeek:attr:`&log` :zeek:attr:`&optional`
                                                                               The inner VLAN for this connection, if applicable.
========================================================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

