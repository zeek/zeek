:tocdepth: 3

base/protocols/smb/smb2-main.zeek
=================================
.. zeek:namespace:: SMB2


:Namespace: SMB2
:Imports: :doc:`base/frameworks/notice/weird.zeek </scripts/base/frameworks/notice/weird.zeek>`, :doc:`base/protocols/smb/main.zeek </scripts/base/protocols/smb/main.zeek>`

Summary
~~~~~~~
Redefinitions
#############
============================================== ==============================================================================================
:zeek:type:`SMB::CmdInfo`: :zeek:type:`record` 
                                               
                                               :New Fields: :zeek:type:`SMB::CmdInfo`
                                               
                                                 smb2_offered_dialects: :zeek:type:`index_vec` :zeek:attr:`&optional`
                                                   Dialects offered by the client.
                                               
                                                 smb2_create_options: :zeek:type:`count` :zeek:attr:`&default` = ``0`` :zeek:attr:`&optional`
                                                   Keep the create_options in the command for
                                                   referencing later.
============================================== ==============================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~

