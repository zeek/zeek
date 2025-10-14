:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_tree_disconnect.bif.zeek
===========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================ ===========================================================================================
:zeek:id:`smb2_tree_disconnect_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 2 requests of type *tree disconnect*.
:zeek:id:`smb2_tree_disconnect_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 2 requests of type *tree disconnect*.
============================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_tree_disconnect_request
   :source-code: base/protocols/smb/smb2-main.zeek 119 127

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the client to logically disconnect
   client access to a server resource.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. zeek:see:: smb2_message

.. zeek:id:: smb2_tree_disconnect_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_tree_disconnect.bif.zeek 26 26

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *tree disconnect*. This is sent by the server to logically disconnect
   client access to a server resource.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   
   .. zeek:see:: smb2_message


