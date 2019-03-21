:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_transform_header.bif.bro
==========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== ===========================================================================================
:bro:id:`smb2_transform_header`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                   version 3.x *transform_header*.
================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_transform_header

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Transform_header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 3.x *transform_header*. This is used by the client or server when sending
   encrypted messages.
   
   For more information, see MS-SMB2:2.2.41
   

   :c: The connection.
   

   :hdr: The parsed transformed header message, which is starting with \xfdSMB and different from SMB1 and SMB2 headers.
   
   .. bro:see:: smb2_message


