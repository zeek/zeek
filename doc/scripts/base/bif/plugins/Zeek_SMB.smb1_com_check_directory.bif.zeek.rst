:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_check_directory.bif.zeek
===========================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================ ===========================================================================================
:zeek:id:`smb1_check_directory_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 1 requests of type *check directory*.
:zeek:id:`smb1_check_directory_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 1 responses of type *check directory*.
============================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_check_directory_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_check_directory.bif.zeek 17 17

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, directory_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *check directory*. This is used by the client to verify that
   a specified path resolves to a valid directory on the server.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param directory_name: The directory name to check for existence.
   
   .. zeek:see:: smb1_message smb1_check_directory_response

.. zeek:id:: smb1_check_directory_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_check_directory.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *check directory*. This is the server response to the
   *check directory* request.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. zeek:see:: smb1_message smb1_check_directory_request


