:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_tree_disconnect.bif.bro
=========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ===========================================================================================
:bro:id:`smb1_tree_disconnect`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                  version 1 requests of type *tree disconnect*.
================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_tree_disconnect

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   
   For more information, see MS-CIFS:2.2.4.51
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :is_orig: True if the message was from the originator.
   
   .. bro:see:: smb1_message


