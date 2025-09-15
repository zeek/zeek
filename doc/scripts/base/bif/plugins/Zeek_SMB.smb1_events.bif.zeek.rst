:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb1_events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
================================================== =========================================================================================================
:zeek:id:`smb1_empty_response`: :zeek:type:`event` Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
:zeek:id:`smb1_error`: :zeek:type:`event`          Generated for :abbr:`SMB (Server Message Block)` version 1 messages
                                                   that indicate an error.
:zeek:id:`smb1_message`: :zeek:type:`event`        Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
                                                   messages.
================================================== =========================================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb1_empty_response
   :source-code: base/bif/plugins/Zeek_SMB.smb1_events.bif.zeek 31 31

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`)

   Generated when there is an :abbr:`SMB (Server Message Block)` version 1 response with no message body.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_error
   :source-code: policy/protocols/smb/log-cmds.zeek 49 64

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)` version 1 messages
   that indicate an error. This event is triggered by an :abbr:`SMB (Server Message Block)` header
   including a status that signals an error.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` message.
   

   :param is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. zeek:see:: smb1_message

.. zeek:id:: smb1_message
   :source-code: base/bif/plugins/Zeek_SMB.smb1_events.bif.zeek 21 21

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB1::Header`, is_orig: :zeek:type:`bool`)

   Generated for all :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` version 1
   messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Zeek's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 1 message.
   

   :param is_orig: True if the message was sent by the originator of the underlying
            transport-level connection.
   
   .. zeek:see:: smb2_message


