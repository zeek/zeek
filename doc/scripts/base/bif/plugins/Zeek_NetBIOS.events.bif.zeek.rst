:tocdepth: 3

base/bif/plugins/Zeek_NetBIOS.events.bif.zeek
=============================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
=========================================================== =====================================================================
:zeek:id:`netbios_session_accepted`: :zeek:type:`event`     Generated for NetBIOS messages of type *positive session response*.
:zeek:id:`netbios_session_keepalive`: :zeek:type:`event`    Generated for NetBIOS messages of type *keep-alive*.
:zeek:id:`netbios_session_message`: :zeek:type:`event`      Generated for all NetBIOS SSN and DGM messages.
:zeek:id:`netbios_session_raw_message`: :zeek:type:`event`  Generated for NetBIOS messages of type *session message* that are not
                                                            carrying an SMB payload.
:zeek:id:`netbios_session_rejected`: :zeek:type:`event`     Generated for NetBIOS messages of type *negative session response*.
:zeek:id:`netbios_session_request`: :zeek:type:`event`      Generated for NetBIOS messages of type *session request*.
:zeek:id:`netbios_session_ret_arg_resp`: :zeek:type:`event` Generated for NetBIOS messages of type *retarget response*.
=========================================================== =====================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: netbios_session_accepted
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 92 92

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *positive session response*. Zeek's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see::  netbios_session_keepalive netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_keepalive
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 217 217

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *keep-alive*. Zeek's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_message
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_message
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 34 34

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg_type: :zeek:type:`count`, data_len: :zeek:type:`count`)

   Generated for all NetBIOS SSN and DGM messages. Zeek's NetBIOS analyzer
   processes the NetBIOS session service running on TCP port 139, and (despite
   its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param is_orig:  True if the message was sent by the originator of the connection.
   

   :param msg_type: The general type of message, as defined in Section 4.3.1 of
             :rfc:`1002`.
   

   :param data_len: The length of the message's payload.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_raw_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp  decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_raw_message
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 157 157

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *session message* that are not
   carrying an SMB payload.
   
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param is_orig: True if the message was sent by the originator of the connection.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header (i.e., the ``user_data``).
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_rejected netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event. In fact, it's probably an odd event
      to have to begin with.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_rejected
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 121 121

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *negative session response*. Zeek's
   NetBIOS analyzer processes the NetBIOS session service running on TCP port
   139, and (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_request
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_request
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 63 63

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *session request*. Zeek's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_ret_arg_resp decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.

.. zeek:id:: netbios_session_ret_arg_resp
   :source-code: base/bif/plugins/Zeek_NetBIOS.events.bif.zeek 188 188

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, msg: :zeek:type:`string`)

   Generated for NetBIOS messages of type *retarget response*. Zeek's NetBIOS
   analyzer processes the NetBIOS session service running on TCP port 139, and
   (despite its name!) the NetBIOS datagram service on UDP port 138.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/NetBIOS>`__ for more information
   about NetBIOS.  :rfc:`1002` describes
   the packet format for NetBIOS over TCP/IP, which Zeek parses.
   

   :param c: The connection, which may be TCP or UDP, depending on the type of the
      NetBIOS session.
   

   :param msg: The raw payload of the message sent, excluding the common NetBIOS
        header.
   
   .. zeek:see:: netbios_session_accepted netbios_session_keepalive
      netbios_session_message netbios_session_raw_message netbios_session_rejected
      netbios_session_request decode_netbios_name decode_netbios_name_type
   
   .. note:: These days, NetBIOS is primarily used as a transport mechanism for
      `SMB/CIFS <http://en.wikipedia.org/wiki/Server_Message_Block>`__. Zeek's
      SMB analyzer parses both SMB-over-NetBIOS and SMB-over-TCP on port 445.
   
   .. todo:: This is an oddly named event.
   
   .. todo:: Zeek's current default configuration does not activate the protocol
      analyzer that generates this event; the corresponding script has not yet
      been ported. To still enable this event, one needs to
      register a port for it or add a DPD payload signature.


