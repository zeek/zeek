:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_com_create_directory.bif.zeek
============================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================= ===========================================================================================
:zeek:id:`smb1_create_directory_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                              version 1 requests of type *create directory*.
:zeek:id:`smb1_create_directory_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                              version 1 responses of type *create directory*.
============================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_create_directory_request
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_create_directory.bif.zeek 18 18

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, directory_name: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is used by the client to
   create a new directory on the server, relative to a connected share.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param directory_name: The name of the directory to create.
   
   .. zeek:see:: smb1_message smb1_create_directory_response smb1_transaction2_request

.. zeek:id:: smb1_create_directory_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_com_create_directory.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *create directory*. This is a deprecated command which
   has been replaced by the *trans2_create_directory* subcommand. This is the server response
   to the *create directory* request.
   
   For more information, see MS-CIFS:2.2.4.1
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. zeek:see:: smb1_message smb1_create_directory_request smb1_transaction2_request


