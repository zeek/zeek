:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_com_create.bif.zeek
==================================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=================================================== ===========================================================================================
:zeek:id:`smb2_create_request`: :zeek:type:`event`  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                    version 2 requests of type *create*.
:zeek:id:`smb2_create_response`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                    version 2 responses of type *create*.
=================================================== ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_create_request
   :source-code: base/protocols/smb/smb2-main.zeek 129 152

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, request: :zeek:type:`SMB2::CreateRequest`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 requests of type *create*. This is sent by the client to request either creation
   of or access to a file.
   
   For more information, see MS-SMB2:2.2.13
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param request: A record with more information related to the request.
   
   .. zeek:see:: smb2_message smb2_create_response

.. zeek:id:: smb2_create_response
   :source-code: base/bif/plugins/Zeek_SMB.smb2_com_create.bif.zeek 33 33

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, response: :zeek:type:`SMB2::CreateResponse`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 responses of type *create*. This is sent by the server to notify the client of
   the status of its SMB2 CREATE request.
   
   For more information, see MS-SMB2:2.2.14
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param response: A record with more information related to the response.
   
   .. zeek:see:: smb2_message smb2_create_request


