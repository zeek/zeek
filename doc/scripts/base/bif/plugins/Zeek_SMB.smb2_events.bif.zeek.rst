:tocdepth: 3

base/bif/plugins/Zeek_SMB.smb2_events.bif.zeek
==============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
============================================================ ===========================================================================================
:zeek:id:`smb2_discarded_messages_state`: :zeek:type:`event` Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 2 connections for which pending read, ioctl or tree requests exceeds
                                                             the :zeek:see:`SMB::max_pending_messages` setting.
:zeek:id:`smb2_message`: :zeek:type:`event`                  Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
                                                             version 2 messages.
============================================================ ===========================================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: smb2_discarded_messages_state
   :source-code: base/protocols/smb/smb2-main.zeek 350 366

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, state: :zeek:type:`string`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 connections for which pending read, ioctl or tree requests exceeds
   the :zeek:see:`SMB::max_pending_messages` setting. This event indicates either
   traffic loss, traffic load-balancing issues, or failures to parse or match
   SMB responses with SMB requests. When this event is raised, internal per-connection
   parser state has been reset.
   

   :param c: The affected connection.
   

   :param state: String describing what kind of state was affected.
          One of read, ioctl or tree.

.. zeek:id:: smb2_message
   :source-code: base/bif/plugins/Zeek_SMB.smb2_events.bif.zeek 20 20

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, hdr: :zeek:type:`SMB2::Header`, is_orig: :zeek:type:`bool`)

   Generated for :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)`
   version 2 messages.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Server_Message_Block>`__ for more information about the
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` protocol. Zeek's
   :abbr:`SMB (Server Message Block)`/:abbr:`CIFS (Common Internet File System)` analyzer parses
   both :abbr:`SMB (Server Message Block)`-over-:abbr:`NetBIOS (Network Basic Input/Output System)` on
   ports 138/139 and :abbr:`SMB (Server Message Block)`-over-TCP on port 445.
   

   :param c: The connection.
   

   :param hdr: The parsed header of the :abbr:`SMB (Server Message Block)` version 2 message.
   

   :param is_orig: True if the message came from the originator side.
   
   .. zeek:see:: smb1_message


