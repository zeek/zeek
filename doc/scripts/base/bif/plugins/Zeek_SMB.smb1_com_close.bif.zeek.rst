:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_close.bif.zeek
=================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ===========================================================================================
:zeek:id:`smb1_close_request`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                  version 1 requests of type *close*.
================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_close_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_close.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, file_id: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *close*. This is used by the client to close an instance of an object
   associated with a valid file ID.
   
   For more information, see MS-CIFS:2.2.4.5
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param file_id: The file identifier being closed.
   
   .. zeek:see:: smb1_message


