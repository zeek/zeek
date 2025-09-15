:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_tree_disconnect.bif.zeek
===========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=================================================== ===========================================================================================
:zeek:id:`smb1_tree_disconnect`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                    version 1 requests of type *tree disconnect*.
=================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_tree_disconnect
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_tree_disconnect.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   
   For more information, see MS-CIFS:2.2.4.51
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param is_orig: True if the message was from the originator.
   
   .. zeek:see:: smb1_message


