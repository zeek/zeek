:tocdepth: 3

base/protocols/smb/smb1-main.zeek
=================================
.. zeek:namespace:: SMB1


:Namespace: SMB1
:Imports: :doc:`base/protocols/smb/main.zeek </scripts/base/protocols/smb/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================== =======================================================================
:zeek:type:`SMB::CmdInfo`: :zeek:type:`record` 
                                               
                                               :New Fields: :zeek:type:`SMB::CmdInfo`
                                               
                                                 smb1_offered_dialects: :zeek:type:`string_vec` :zeek:attr:`&optional`
                                                   Dialects offered by the client.
============================================== =======================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

