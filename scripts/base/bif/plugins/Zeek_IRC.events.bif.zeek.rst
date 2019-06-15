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

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, chans: :zeek:type:`count`)

   Generated for an IRC reply of type *luserchannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :chans: The number of channels as returned in the reply.
   
   .. zeek:see::  irc_channel_topic irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_channel_topic

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, channel: :zeek:type:`string`, topic: :zeek:type:`string`)

   Generated for an IRC reply of type *topic*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :channel: The channel name specified in the reply.
   

   :topic: The topic specified in the reply.
   
   .. zeek:see:: irc_channel_info  irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_dcc_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, target: :zeek:type:`string`, dcc_type: :zeek:type:`string`, argument: :zeek:type:`string`, address: :zeek:type:`addr`, dest_port: :zeek:type:`count`, size: :zeek:type:`count`)

   Generated for IRC messages of type *dcc*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :target: The target specified in the message.
   

   :dcc_type: The DCC type specified in the message.
   

   :argument:  The argument specified in the message.
   

   :address: The address specified in the message.
   

   :dest_port: The destination port specified in the message.
   

   :size: The size specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic  irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_error_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *error*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :message: The textual description specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_global_users

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, msg: :zeek:type:`string`)

   Generated for an IRC reply of type *globalusers*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :msg: The message coming with the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_invalid_nick

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`)

   Generated when a server rejects an IRC nickname.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users  irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_invite_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, nickname: :zeek:type:`string`, channel: :zeek:type:`string`)

   Generated for IRC messages of type *invite*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :nickname: The nickname specified in the message.
   

   :channel: The channel specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick  irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_join_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, info_list: :zeek:type:`irc_join_list`)

   Generated for IRC messages of type *join*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :info_list: The user information coming with the command.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_kick_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, chans: :zeek:type:`string`, users: :zeek:type:`string`, comment: :zeek:type:`string`)

   Generated for IRC messages of type *kick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :chans: The channels specified in the message.
   

   :users: The users specified in the message.
   

   :comment: The comment specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, command: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC commands forwarded from the server to the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :command: The command.
   

   :message: TODO.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message  irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message
   
   .. note::
   
      This event is generated only for messages that are forwarded by the server
      to the client. Commands coming from client trigger the
      :zeek:id:`irc_request` event instead.

.. zeek:id:: irc_mode_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, params: :zeek:type:`string`)

   Generated for IRC messages of type *mode*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :params: The parameters coming with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message  irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_names_info

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, c_type: :zeek:type:`string`, channel: :zeek:type:`string`, users: :zeek:type:`string_set`)

   Generated for an IRC reply of type *namereply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :c_type: The channel type.
   

   :channel: The channel.
   

   :users: The set of users.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message  irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_network_info

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, users: :zeek:type:`count`, services: :zeek:type:`count`, servers: :zeek:type:`count`)

   Generated for an IRC reply of type *luserclient*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :users: The number of users as returned in the reply.
   

   :services: The number of services as returned in the reply.
   

   :servers: The number of servers as returned in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_nick_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, who: :zeek:type:`string`, newnick: :zeek:type:`string`)

   Generated for IRC messages of type *nick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :who: The user changing its nickname.
   

   :newnick: The new nickname.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_notice_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *notice*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :source: The source of the private communication.
   

   :target: The target of the private communication.
   

   :message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message  irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_oper_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, password: :zeek:type:`string`)

   Generated for IRC messages of type *oper*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :user: The user specified in the message.
   

   :password: The password specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message  irc_oper_response irc_part_message
      irc_password_message

.. zeek:id:: irc_oper_response

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, got_oper: :zeek:type:`bool`)

   Generated for IRC replies of type *youreoper* and *nooperhost*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :got_oper: True if the *oper* command was executed successfully
             (*youreport*) and false otherwise (*nooperhost*).
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_part_message
      irc_password_message

.. zeek:id:: irc_part_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, chans: :zeek:type:`string_set`, message: :zeek:type:`string`)

   Generated for IRC messages of type *part*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname coming with the message.
   

   :chans: The set of channels affected.
   

   :message: The text coming with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_password_message

.. zeek:id:: irc_password_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, password: :zeek:type:`string`)

   Generated for IRC messages of type *password*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :password: The password specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message

.. zeek:id:: irc_privmsg_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *privmsg*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :source: The source of the private communication.
   

   :target: The target of the private communication.
   

   :message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_quit_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *quit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname coming with the message.
   

   :message: The text included with the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_reply

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, code: :zeek:type:`count`, params: :zeek:type:`string`)

   Generated for all IRC replies. IRC replies are sent in response to a
   request and come with a reply code.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the reply. IRC uses the prefix to
           indicate the true origin of a message.
   

   :code: The reply code, as specified by the protocol.
   

   :params: The reply's parameters.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_request

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, command: :zeek:type:`string`, arguments: :zeek:type:`string`)

   Generated for all client-side IRC commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: Always true.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :command: The command.
   

   :arguments: The arguments for the command.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message
   
   .. note:: This event is generated only for messages that originate
      at the client-side. Commands coming in from remote trigger
      the :zeek:id:`irc_message` event instead.

.. zeek:id:: irc_server_info

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, users: :zeek:type:`count`, services: :zeek:type:`count`, servers: :zeek:type:`count`)

   Generated for an IRC reply of type *luserme*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :users: The number of users as returned in the reply.
   

   :services: The number of services as returned in the reply.
   

   :servers: The number of servers as returned in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_squery_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, source: :zeek:type:`string`, target: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *squery*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :source: The source of the private communication.
   

   :target: The target of the private communication.
   

   :message: The text of communication.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_squit_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, prefix: :zeek:type:`string`, server: :zeek:type:`string`, message: :zeek:type:`string`)

   Generated for IRC messages of type *squit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :server: The server specified in the message.
   

   :message: The textual description specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_starttls

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`)

   Generated if an IRC connection switched to TLS using STARTTLS. After this
   event no more IRC events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :c: The connection.

.. zeek:id:: irc_user_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, user: :zeek:type:`string`, host: :zeek:type:`string`, server: :zeek:type:`string`, real_name: :zeek:type:`string`)

   Generated for IRC messages of type *user*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :user: The user specified in the message.
   

   :host: The host name specified in the message.
   

   :server: The server name specified in the message.
   

   :real_name: The real name specified in the message.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_who_line

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, target_nick: :zeek:type:`string`, channel: :zeek:type:`string`, user: :zeek:type:`string`, host: :zeek:type:`string`, server: :zeek:type:`string`, nick: :zeek:type:`string`, params: :zeek:type:`string`, hops: :zeek:type:`count`, real_name: :zeek:type:`string`)

   Generated for an IRC reply of type *whoreply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :target_nick: The target nickname.
   

   :channel: The channel.
   

   :user: The user.
   

   :host: The host.
   

   :server: The server.
   

   :nick: The nickname.
   

   :params: The parameters.
   

   :hops: The hop count.
   

   :real_name: The real name.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_who_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, mask: :zeek:type:`string`, oper: :zeek:type:`bool`)

   Generated for IRC messages of type *who*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :mask: The mask specified in the message.
   

   :oper: True if the operator flag was set.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_whois_channel_line

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, chans: :zeek:type:`string_set`)

   Generated for an IRC reply of type *whoischannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   

   :chans: The set of channels returned.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_whois_message

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, server: :zeek:type:`string`, users: :zeek:type:`string`)

   Generated for IRC messages of type *whois*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :server: TODO.
   

   :users: TODO.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_whois_operator_line

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`)

   Generated for an IRC reply of type *whoisoperator*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. zeek:id:: irc_whois_user_line

   :Type: :zeek:type:`event` (c: :zeek:type:`connection`, is_orig: :zeek:type:`bool`, nick: :zeek:type:`string`, user: :zeek:type:`string`, host: :zeek:type:`string`, real_name: :zeek:type:`string`)

   Generated for an IRC reply of type *whoisuser*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   

   :user: The user name specified in the reply.
   

   :host: The host name specified in the reply.
   

   :real_name: The real name specified in the reply.
   
   .. zeek:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message


