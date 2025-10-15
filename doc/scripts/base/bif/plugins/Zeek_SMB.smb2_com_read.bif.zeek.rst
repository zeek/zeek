:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_read.bif.zeek
================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ ===========================================================================================
:zeek:id:`smb2_read_request`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                 version 2 requests of type *read*.
================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_read_request
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_read.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, file_id: :zeek:type:`SMB2::GUID`, offset: :zeek:type:`count`, length: :zeek:type:`count`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *read*. This is sent by the client to request a read operation on
   the specified file.
   
   For more information, see MS-SMB2:2.2.19
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param file_id: The GUID being used for the file.
   

   :param offset: How far into the file this read should be taking place.
   

   :param length: The number of bytes of the file being read.
   
   .. zeek:see:: smb2_message


