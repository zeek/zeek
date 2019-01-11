:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_close.bif.bro
===============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=============================================== ===========================================================================================
:bro:id:`smb1_close_request`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                version 1 requests of type *close*.
=============================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_close_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, file_id: :bro:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *close*. This is used by the client to close an instance of an object
   associated with a valid file ID.
   
   For more information, see MS-CIFS:2.2.4.5
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :file_id: The file identifier being closed.
   
   .. bro:see:: smb1_message


