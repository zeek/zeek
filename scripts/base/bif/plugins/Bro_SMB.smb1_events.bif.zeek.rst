:tocdepth: 3

base/bif/plugins/Bro_SMB.smb1_events.bif.zeek
=============================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================ =========================================================================================================
:bro:id:`smb1_empty_response`: :bro:type:`event` Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
:bro:id:`smb1_error`: :bro:type:`event`          Generated for :abbr:`SMB (Server Message Block)` version 1 messages
                                                 that indicate an error.
:bro:id:`smb1_message`: :bro:type:`event`        Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
                                                 messages.
================================================ =========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: smb1_empty_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`)

   Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_error

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, is_orig: :bro:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)` version 1 messages
   that indicate an error. This event is triggered by an :abbr:`SMB (Server Message Block)` header
   including a status that signals an error.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   

   :is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. bro:see:: smb1_message

.. bro:id:: smb1_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, hdr: :bro:type:`SMB1::Header`, is_orig: :bro:type:`bool`)

   Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
   messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Bro's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :c: The connection.
   

   :hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. bro:see:: smb2_message


