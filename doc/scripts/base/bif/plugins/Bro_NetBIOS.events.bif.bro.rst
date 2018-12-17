:tocdepth: 3

base/bif/plugins/Bro_NetBIOS.events.bif.bro
===========================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
========================================================= =====================================================================
:bro:id:`netbios_session_accepted`: :bro:type:`event`     Generated for NetBIOS messages of type *positive session response*.
:bro:id:`netbios_session_keepalive`: :bro:type:`event`    Generated for NetBIOS messages of type *keep-alive*.
:bro:id:`netbios_session_message`: :bro:type:`event`      Generated for all NetBIOS SSN and DGM messages.
:bro:id:`netbios_session_raw_message`: :bro:type:`event`  Generated for NetBIOS messages of type *session message* that are not
                                                          carrying an SMB payload.
:bro:id:`netbios_session_rejected`: :bro:type:`event`     Generated for NetBIOS messages of type *negative session response*.
:bro:id:`netbios_session_request`: :bro:type:`event`      Generated for NetBIOS messages of type *session request*.
:bro:id:`netbios_session_ret_arg_resp`: :bro:type:`event` Generated for NetBIOS messages of type *retarget response*.
========================================================= =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: netbios_session_accepted

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *positive session response*. Bro's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see::  netbios_session_keepalive netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_keepalive

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *keep-alive*. Bro's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg_type: :bro:type:`count`, data_len: :bro:type:`count`)

   Generated for all NetBIOS SSN and DGM messages. Bro's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :is_orig:  True if the message was sent by the originator of the connection.
   

   :msg_type: The general type of message, as defined in Section 4.3.1 of
             :rfc:`1002`.
   

   :data_len: The length of the message's payload.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp  decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_raw_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *session message* that are not
   carrying an SMB payload.
   
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :is_orig: True if the message was sent by the originator of the connection.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header (i.e., the ``user_data``).
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event. In fact, it's probably an odd event
      to have to begin with.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_rejected

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *negative session response*. Bro's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *session request*. Bro's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. bro:id:: netbios_session_ret_arg_resp

   :Type: :bro:type:`event` (c: :bro:type:`connection`, msg: :bro:type:`string`)

   Generated for NetBIOS messages of type *retarget response*. Bro's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Bro parses.
   

   :c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. bro:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_request decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Bro's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event.
   
   .. todo:: Bro's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported to Bro 2.x. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


