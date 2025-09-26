:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_transform_header.bif.zeek
============================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ===========================================================================================
:zeek:id:`smb2_transform_header`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                     version 3.x *transform_header*.
==================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_transform_header
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_transform_header.bif.zeek 15 15

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Transform_header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 3.x *transform_header*. This is used by the client or server when sending
   encrypted messages.
   
   For more information, see MS-SMB2:2.2.41
   

   :param c: The connection.
   

   :param hdr: The parsed transformed header message, which is starting with \xfdSMB and different from SMB1 and SMB2 headers.
   
   .. zeek:see:: smb2_message


