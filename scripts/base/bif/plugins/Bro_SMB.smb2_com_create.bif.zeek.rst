:tocdepth: 3

base/bif/plugins/Bro_SMB.smb2_com_create.bif.zeek
=================================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================= ===========================================================================================
:bro:id:`smb2_create_request`: :bro:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                  version 2 requests of type *create*.
:bro:id:`smb2_create_response`: :bro:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                  version 2 responses of type *create*.
================================================= ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb2_create_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, request: :bro:type:`SMB2::CreateRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *create*. This is sent by the client to request either creation
   of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :request: A record with more information related to the request.
   
   .. bro:see:: smb2_message smb2_create_response

.. bro:id:: smb2_create_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB2::Header`, response: :bro:type:`SMB2::CreateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *create*. This is sent by the server to notify the client of
   the status of its SMB2 CREATE request.
   
   For more information, see MS-SMB2:2.2.14
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :response: A record with more information related to the response.
   
   .. bro:see:: smb2_message smb2_create_request


