:tocdepth: 3

base/bif/plugins/Zeek_IRC.events.bif.zeek
=========================================
.. zeek:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
====================================================== ===================================================================
:zeek:id:`irc_channel_info`: :zeek:type:`event`        Generated for an IRC reply of type *luserchannels*.
:zeek:id:`irc_channel_topic`: :zeek:type:`event`       Generated for an IRC reply of type *topic*.
:zeek:id:`irc_dcc_message`: :zeek:type:`event`         Generated for IRC messages of type *dcc*.
:zeek:id:`irc_dcc_send_ack`: :zeek:type:`event`        Generated for IRC messages of type *dcc*.
:zeek:id:`irc_error_message`: :zeek:type:`event`       Generated for IRC messages of type *error*.
:zeek:id:`irc_global_users`: :zeek:type:`event`        Generated for an IRC reply of type *globalusers*.
:zeek:id:`irc_invalid_nick`: :zeek:type:`event`        Generated when a server rejects an IRC nickname.
:zeek:id:`irc_invite_message`: :zeek:type:`event`      Generated for IRC messages of type *invite*.
:zeek:id:`irc_join_message`: :zeek:type:`event`        Generated for IRC messages of type *join*.
:zeek:id:`irc_kick_message`: :zeek:type:`event`        Generated for IRC messages of type *kick*.
:zeek:id:`irc_message`: :zeek:type:`event`             Generated for IRC commands forwarded from the server to the client.
:zeek:id:`irc_mode_message`: :zeek:type:`event`        Generated for IRC messages of type *mode*.
:zeek:id:`irc_names_info`: :zeek:type:`event`          Generated for an IRC reply of type *namereply*.
:zeek:id:`irc_network_info`: :zeek:type:`event`        Generated for an IRC reply of type *luserclient*.
:zeek:id:`irc_nick_message`: :zeek:type:`event`        Generated for IRC messages of type *nick*.
:zeek:id:`irc_notice_message`: :zeek:type:`event`      Generated for IRC messages of type *notice*.
:zeek:id:`irc_oper_message`: :zeek:type:`event`        Generated for IRC messages of type *oper*.
:zeek:id:`irc_oper_response`: :zeek:type:`event`       Generated for IRC replies of type *youreoper* and *nooperhost*.
:zeek:id:`irc_part_message`: :zeek:type:`event`        Generated for IRC messages of type *part*.
:zeek:id:`irc_password_message`: :zeek:type:`event`    Generated for IRC messages of type *password*.
:zeek:id:`irc_privmsg_message`: :zeek:type:`event`     Generated for IRC messages of type *privmsg*.
:zeek:id:`irc_quit_message`: :zeek:type:`event`        Generated for IRC messages of type *quit*.
:zeek:id:`irc_reply`: :zeek:type:`event`               Generated for all IRC replies.
:zeek:id:`irc_request`: :zeek:type:`event`             Generated for all client-side IRC commands.
:zeek:id:`irc_server_info`: :zeek:type:`event`         Generated for an IRC reply of type *luserme*.
:zeek:id:`irc_squery_message`: :zeek:type:`event`      Generated for IRC messages of type *squery*.
:zeek:id:`irc_squit_message`: :zeek:type:`event`       Generated for IRC messages of type *squit*.
:zeek:id:`irc_starttls`: :zeek:type:`event`            Generated if an IRC connection switched to TLS using STARTTLS.
:zeek:id:`irc_user_message`: :zeek:type:`event`        Generated for IRC messages of type *user*.
:zeek:id:`irc_who_line`: :zeek:type:`event`            Generated for an IRC reply of type *whoreply*.
:zeek:id:`irc_who_message`: :zeek:type:`event`         Generated for IRC messages of type *who*.
:zeek:id:`irc_whois_channel_line`: :zeek:type:`event`  Generated for an IRC reply of type *whoischannels*.
:zeek:id:`irc_whois_message`: :zeek:type:`event`       Generated for IRC messages of type *whois*.
:zeek:id:`irc_whois_operator_line`: :zeek:type:`event` Generated for an IRC reply of type *whoisoperator*.
:zeek:id:`irc_whois_user_line`: :zeek:type:`event`     Generated for an IRC reply of type *whoisuser*.
====================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. zeek:id:: irc_channel_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 339 339

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, chans: :zeek:type:`count`)

   Generated for an IRC reply of type *luserchannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param chans: The number of channels as returned in the reply.
   
   .. zeek:see::  irc_channel_topic irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_channel_topic
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 534 534

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, channel: :zeek:type:`string`, topic: :zeek:type:`string`)

   Generated for an IRC reply of type *topic*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param channel: The channel name specified in the reply.
   

   :param topic: The topic specified in the reply.
   
   .. zeek:see:: irc_channel_info  irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_dcc_message
   :source-code: base/protocols/irc/dcc-send.zeek 109 123

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, target: :zeek:type:`string`, dcc_type: :zeek:type:`string`, argument: :zeek:type:`string`, address: :zeek:type:`addr`, dest_port: :zeek:type:`count`, size: :zeek:type:`count`)

   Generated for IRC messages of type *dcc*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Direct_Client-to-Client>`__ for more
   information about the DCC.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param target: The target specified in the message.
   

   :param dcc_type: The DCC type specified in the message.
   

   :param argument:  The argument specified in the message.
   

   :param address: The address specified in the message.
   

   :param dest_port: The destination port specified in the message.
   

   :param size: The size specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic  irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_dcc_send_ack
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 789 789

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, bytes_received: :zeek:type:`count`)

   Generated for IRC messages of type *dcc*. This event is generated for
   DCC SEND acknowledge message.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   
   See `Wikipedia <https://en.wikipedia.org/wiki/Direct_Client-to-Client>`__ for more
   information about the DCC.
   

   :param c: The connection.
   

   :param bytes_received: The number of bytes received as reported by the recipient.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_error_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 655 655

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *error*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param message: The textual description specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_global_users
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 512 512

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, msg: :zeek:type:`string`)

   Generated for an IRC reply of type *globalusers*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param msg: The message coming with the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_invalid_nick
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 271 271

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when a server rejects an IRC nickname.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users  irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_invite_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 681 681

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, nickname: :zeek:type:`string`, channel: :zeek:type:`string`)

   Generated for IRC messages of type *invite*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param nickname: The nickname specified in the message.
   

   :param channel: The channel specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick  irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_join_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 205 205

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, info_list: :zeek:type:`irc_join_list`)

   Generated for IRC messages of type *join*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param info_list: The user information coming with the command.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_kick_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 631 631

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, chans: :zeek:type:`string`, users: :zeek:type:`string`, comment: :zeek:type:`string`)

   Generated for IRC messages of type *kick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param chans: The channels specified in the message.
   

   :param users: The users specified in the message.
   

   :param comment: The comment specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 86 86

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, command: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC commands forwarded from the server to the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: Always false.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param command: The command.
   

   :param message: TODO.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message  irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack
   
   .. note::
   
      This event is generated only for messages that are forwarded by the server
      to the client. Commands coming from client trigger the
      :zeek:id:`irc_request` event instead.

.. zeek:id:: irc_mode_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 705 705

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, params: :zeek:type:`string`)

   Generated for IRC messages of type *mode*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param params: The parameters coming with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message  irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_names_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 400 400

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, c_type: :zeek:type:`string`, channel: :zeek:type:`string`, users: :zeek:type:`string_set`)

   Generated for an IRC reply of type *namereply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param c_type: The channel type.
   

   :param channel: The channel.
   

   :param users: The set of users.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message  irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_network_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 295 295

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, users: :zeek:type:`count`, services: :zeek:type:`count`, servers: :zeek:type:`count`)

   Generated for an IRC reply of type *luserclient*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param users: The number of users as returned in the reply.
   

   :param services: The number of services as returned in the reply.
   

   :param servers: The number of servers as returned in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_nick_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 253 253

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, who: :zeek:type:`string`, newnick: :zeek:type:`string`)

   Generated for IRC messages of type *nick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param who: The user changing its nickname.
   

   :param newnick: The new nickname.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_notice_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 159 159

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *notice*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param source: The source of the private communication.
   

   :param target: The target of the private communication.
   

   :param message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message  irc_oper_message irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_oper_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 603 603

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for IRC messages of type *oper*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param user: The user specified in the message.
   

   :param password: The password specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message  irc_oper_response irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_oper_response
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 489 489

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, got_oper: :zeek:type:`bool`)

   Generated for IRC replies of type *youreoper* and *nooperhost*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param got_oper: True if the *oper* command was executed successfully
             (*youreport*) and false otherwise (*nooperhost*).
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_part_message
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_part_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 230 230

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, chans: :zeek:type:`string_set`, message: :zeek:type:`string`)

   Generated for IRC messages of type *part*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname coming with the message.
   

   :param chans: The set of channels affected.
   

   :param message: The text coming with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_password_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 837 837

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, password: :zeek:type:`string`)

   Generated for IRC messages of type *password*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param password: The password specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_dcc_send_ack

.. zeek:id:: irc_privmsg_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 134 134

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *privmsg*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param source: The source of the private communication.
   

   :param target: The target of the private communication.
   

   :param message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_quit_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 109 109

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *quit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname coming with the message.
   

   :param message: The text included with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_reply
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 56 56

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, code: :zeek:type:`count`, params: :zeek:type:`string`)

   Generated for all IRC replies. IRC replies are sent in response to a
   request and come with a reply code.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the reply. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param code: The reply code, as specified by the protocol.
   

   :param params: The reply's parameters.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_request
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 30 30

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, command: :zeek:type:`string`, arguments: :zeek:type:`string`)

   Generated for all client-side IRC commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: Always true.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param command: The command.
   

   :param arguments: The arguments for the command.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack
   
   .. note:: This event is generated only for messages that originate
      at the client-side. Commands coming in from remote trigger
      the :zeek:id:`irc_message` event instead.

.. zeek:id:: irc_server_info
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 319 319

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, users: :zeek:type:`count`, services: :zeek:type:`count`, servers: :zeek:type:`count`)

   Generated for an IRC reply of type *luserme*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param users: The number of users as returned in the reply.
   

   :param services: The number of services as returned in the reply.
   

   :param servers: The number of servers as returned in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_squery_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 184 184

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *squery*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param source: The source of the private communication.
   

   :param target: The target of the private communication.
   

   :param message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_squit_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 731 731

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, server: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *squit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :param server: The server specified in the message.
   

   :param message: The textual description specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_starttls
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 845 845

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated if an IRC connection switched to TLS using STARTTLS. After this
   event no more IRC events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :param c: The connection.

.. zeek:id:: irc_user_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 816 816

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, host: :zeek:type:`string`, server: :zeek:type:`string`, real_name: :zeek:type:`string`)

   Generated for IRC messages of type *user*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param user: The user specified in the message.
   

   :param host: The host name specified in the message.
   

   :param server: The server name specified in the message.
   

   :param real_name: The real name specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_who_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 375 375

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, target_nick: :zeek:type:`string`, channel: :zeek:type:`string`, user: :zeek:type:`string`, host: :zeek:type:`string`, server: :zeek:type:`string`, nick: :zeek:type:`string`, params: :zeek:type:`string`, hops: :zeek:type:`count`, real_name: :zeek:type:`string`)

   Generated for an IRC reply of type *whoreply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param target_nick: The target nickname.
   

   :param channel: The channel.
   

   :param user: The user.
   

   :param host: The host.
   

   :param server: The server.
   

   :param nick: The nickname.
   

   :param params: The parameters.
   

   :param hops: The hop count.
   

   :param real_name: The real name.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_who_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 557 557

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, mask: :zeek:type:`string`, oper: :zeek:type:`bool`)

   Generated for IRC messages of type *who*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param mask: The mask specified in the message.
   

   :param oper: True if the operator flag was set.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_channel_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 442 442

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, chans: :zeek:type:`string_set`)

   Generated for an IRC reply of type *whoischannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname specified in the reply.
   

   :param chans: The set of channels returned.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_message
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 580 580

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, server: :zeek:type:`string`, users: :zeek:type:`string`)

   Generated for IRC messages of type *whois*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param server: TODO.
   

   :param users: TODO.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_operator_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 420 420

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`)

   Generated for an IRC reply of type *whoisoperator*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname specified in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack

.. zeek:id:: irc_whois_user_line
   :source-code: base/bif/plugins/Zeek_IRC.events.bif.zeek 468 468

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, user: :zeek:type:`string`, host: :zeek:type:`string`, real_name: :zeek:type:`string`)

   Generated for an IRC reply of type *whoisuser*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :param c: The connection.
   

   :param is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :param nick: The nickname specified in the reply.
   

   :param user: The user name specified in the reply.
   

   :param host: The host name specified in the reply.
   

   :param real_name: The real name specified in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message irc_dcc_send_ack


