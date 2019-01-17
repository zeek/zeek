:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_com_check_directory.bif.bro
=========================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================== ===========================================================================================
:bro:id:`smb1_check_directory_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                           version 1 requests of type *check directory*.
:bro:id:`smb1_check_directory_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                           version 1 responses of type *check directory*.
========================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_check_directory_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, directory_name: :bro:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 requests of type *check directory*. This is used by the client to verify that
   a specified path resolves to a valid directory on the server.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :directory_name: The directory name to check for existence.
   
   .. bro:see:: smb1_message smb1_check_directory_response

.. bro:id:: smb1_check_directory_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 1 responses of type *check directory*. This is the server response to the
   *check directory* request.
   
   For more information, see MS-CIFS:2.2.4.17
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   
   .. bro:see:: smb1_message smb1_check_directory_request


