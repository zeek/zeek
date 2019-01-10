:tocdepth: 3

base/bif/plugins/Bro_IRC.events.bif.bro
=======================================
.. bro:namespace:: GLOBAL


:Namespace: GLOBAL

Summary
~~~~~~~
Events
######
==================================================== ===================================================================
:bro:id:`irc_channel_info`: :bro:type:`event`        Generated for an IRC reply of type *luserchannels*.
:bro:id:`irc_channel_topic`: :bro:type:`event`       Generated for an IRC reply of type *topic*.
:bro:id:`irc_dcc_message`: :bro:type:`event`         Generated for IRC messages of type *dcc*.
:bro:id:`irc_error_message`: :bro:type:`event`       Generated for IRC messages of type *error*.
:bro:id:`irc_global_users`: :bro:type:`event`        Generated for an IRC reply of type *globalusers*.
:bro:id:`irc_invalid_nick`: :bro:type:`event`        Generated when a server rejects an IRC nickname.
:bro:id:`irc_invite_message`: :bro:type:`event`      Generated for IRC messages of type *invite*.
:bro:id:`irc_join_message`: :bro:type:`event`        Generated for IRC messages of type *join*.
:bro:id:`irc_kick_message`: :bro:type:`event`        Generated for IRC messages of type *kick*.
:bro:id:`irc_message`: :bro:type:`event`             Generated for IRC commands forwarded from the server to the client.
:bro:id:`irc_mode_message`: :bro:type:`event`        Generated for IRC messages of type *mode*.
:bro:id:`irc_names_info`: :bro:type:`event`          Generated for an IRC reply of type *namereply*.
:bro:id:`irc_network_info`: :bro:type:`event`        Generated for an IRC reply of type *luserclient*.
:bro:id:`irc_nick_message`: :bro:type:`event`        Generated for IRC messages of type *nick*.
:bro:id:`irc_notice_message`: :bro:type:`event`      Generated for IRC messages of type *notice*.
:bro:id:`irc_oper_message`: :bro:type:`event`        Generated for IRC messages of type *oper*.
:bro:id:`irc_oper_response`: :bro:type:`event`       Generated for IRC replies of type *youreoper* and *nooperhost*.
:bro:id:`irc_part_message`: :bro:type:`event`        Generated for IRC messages of type *part*.
:bro:id:`irc_password_message`: :bro:type:`event`    Generated for IRC messages of type *password*.
:bro:id:`irc_privmsg_message`: :bro:type:`event`     Generated for IRC messages of type *privmsg*.
:bro:id:`irc_quit_message`: :bro:type:`event`        Generated for IRC messages of type *quit*.
:bro:id:`irc_reply`: :bro:type:`event`               Generated for all IRC replies.
:bro:id:`irc_request`: :bro:type:`event`             Generated for all client-side IRC commands.
:bro:id:`irc_server_info`: :bro:type:`event`         Generated for an IRC reply of type *luserme*.
:bro:id:`irc_squery_message`: :bro:type:`event`      Generated for IRC messages of type *squery*.
:bro:id:`irc_squit_message`: :bro:type:`event`       Generated for IRC messages of type *squit*.
:bro:id:`irc_starttls`: :bro:type:`event`            Generated if an IRC connection switched to TLS using STARTTLS.
:bro:id:`irc_user_message`: :bro:type:`event`        Generated for IRC messages of type *user*.
:bro:id:`irc_who_line`: :bro:type:`event`            Generated for an IRC reply of type *whoreply*.
:bro:id:`irc_who_message`: :bro:type:`event`         Generated for IRC messages of type *who*.
:bro:id:`irc_whois_channel_line`: :bro:type:`event`  Generated for an IRC reply of type *whoischannels*.
:bro:id:`irc_whois_message`: :bro:type:`event`       Generated for IRC messages of type *whois*.
:bro:id:`irc_whois_operator_line`: :bro:type:`event` Generated for an IRC reply of type *whoisoperator*.
:bro:id:`irc_whois_user_line`: :bro:type:`event`     Generated for an IRC reply of type *whoisuser*.
==================================================== ===================================================================


Detailed Interface
~~~~~~~~~~~~~~~~~~
Events
######
.. bro:id:: irc_channel_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, chans: :bro:type:`count`)

   Generated for an IRC reply of type *luserchannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :chans: The number of channels as returned in the reply.
   
   .. bro:see::  irc_channel_topic irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_channel_topic

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, channel: :bro:type:`string`, topic: :bro:type:`string`)

   Generated for an IRC reply of type *topic*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :channel: The channel name specified in the reply.
   

   :topic: The topic specified in the reply.
   
   .. bro:see:: irc_channel_info  irc_dcc_message irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_dcc_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, target: :bro:type:`string`, dcc_type: :bro:type:`string`, argument: :bro:type:`string`, address: :bro:type:`addr`, dest_port: :bro:type:`count`, size: :bro:type:`count`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic  irc_error_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_error_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, message: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_global_users
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_global_users

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, msg: :bro:type:`string`)

   Generated for an IRC reply of type *globalusers*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :msg: The message coming with the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_invalid_nick irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_invalid_nick

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`)

   Generated when a server rejects an IRC nickname.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users  irc_invite_message irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_invite_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, nickname: :bro:type:`string`, channel: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick  irc_join_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_join_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, info_list: :bro:type:`irc_join_list`)

   Generated for IRC messages of type *join*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :info_list: The user information coming with the command.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_kick_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_kick_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, chans: :bro:type:`string`, users: :bro:type:`string`, comment: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_message irc_mode_message irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, command: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC commands forwarded from the server to the client.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: Always false.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :command: The command.
   

   :message: TODO.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message  irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message
   
   .. note::
   
      This event is generated only for messages that are forwarded by the server
      to the client. Commands coming from client trigger the
      :bro:id:`irc_request` event instead.

.. bro:id:: irc_mode_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, params: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message  irc_names_info irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_names_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, c_type: :bro:type:`string`, channel: :bro:type:`string`, users: :bro:type:`string_set`)

   Generated for an IRC reply of type *namereply*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :c_type: The channel type.
   

   :channel: The channel.
   

   :users: The set of users.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message  irc_network_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_network_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, users: :bro:type:`count`, services: :bro:type:`count`, servers: :bro:type:`count`)

   Generated for an IRC reply of type *luserclient*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :users: The number of users as returned in the reply.
   

   :services: The number of services as returned in the reply.
   

   :servers: The number of servers as returned in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_nick_message
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_nick_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, who: :bro:type:`string`, newnick: :bro:type:`string`)

   Generated for IRC messages of type *nick*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :who: The user changing its nickname.
   

   :newnick: The new nickname.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_notice_message irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_notice_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, source: :bro:type:`string`, target: :bro:type:`string`, message: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message  irc_oper_message irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_oper_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, password: :bro:type:`string`)

   Generated for IRC messages of type *oper*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :user: The user specified in the message.
   

   :password: The password specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message  irc_oper_response irc_part_message
      irc_password_message

.. bro:id:: irc_oper_response

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, got_oper: :bro:type:`bool`)

   Generated for IRC replies of type *youreoper* and *nooperhost*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :got_oper: True if the *oper* command was executed successfully
             (*youreport*) and false otherwise (*nooperhost*).
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_part_message
      irc_password_message

.. bro:id:: irc_part_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, chans: :bro:type:`string_set`, message: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_password_message

.. bro:id:: irc_password_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, password: :bro:type:`string`)

   Generated for IRC messages of type *password*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :password: The password specified in the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message

.. bro:id:: irc_privmsg_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, source: :bro:type:`string`, target: :bro:type:`string`, message: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_quit_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, message: :bro:type:`string`)

   Generated for IRC messages of type *quit*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname coming with the message.
   

   :message: The text included with the message.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_reply

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, code: :bro:type:`count`, params: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_request

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, command: :bro:type:`string`, arguments: :bro:type:`string`)

   Generated for all client-side IRC commands.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: Always true.
   

   :prefix: The optional prefix coming with the command. IRC uses the prefix to
           indicate the true origin of a message.
   

   :command: The command.
   

   :arguments: The arguments for the command.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message
   
   .. note:: This event is generated only for messages that originate
      at the client-side. Commands coming in from remote trigger
      the :bro:id:`irc_message` event instead.

.. bro:id:: irc_server_info

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, users: :bro:type:`count`, services: :bro:type:`count`, servers: :bro:type:`count`)

   Generated for an IRC reply of type *luserme*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :users: The number of users as returned in the reply.
   

   :services: The number of services as returned in the reply.
   

   :servers: The number of servers as returned in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_squery_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, source: :bro:type:`string`, target: :bro:type:`string`, message: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_squit_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, prefix: :bro:type:`string`, server: :bro:type:`string`, message: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_starttls

   :Type: :bro:type:`event` (c: :bro:type:`connection`)

   Generated if an IRC connection switched to TLS using STARTTLS. After this
   event no more IRC events will be raised for the connection. See the SSL
   analyzer for related SSL events, which will now be generated.
   

   :c: The connection.

.. bro:id:: irc_user_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, user: :bro:type:`string`, host: :bro:type:`string`, server: :bro:type:`string`, real_name: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_who_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, target_nick: :bro:type:`string`, channel: :bro:type:`string`, user: :bro:type:`string`, host: :bro:type:`string`, server: :bro:type:`string`, nick: :bro:type:`string`, params: :bro:type:`string`, hops: :bro:type:`count`, real_name: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_who_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, mask: :bro:type:`string`, oper: :bro:type:`bool`)

   Generated for IRC messages of type *who*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :mask: The mask specified in the message.
   

   :oper: True if the operator flag was set.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_channel_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, chans: :bro:type:`string_set`)

   Generated for an IRC reply of type *whoischannels*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   

   :chans: The set of channels returned.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_message

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, server: :bro:type:`string`, users: :bro:type:`string`)

   Generated for IRC messages of type *whois*. This event is generated for
   messages coming from both the client and the server.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :server: TODO.
   

   :users: TODO.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_operator_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`)

   Generated for an IRC reply of type *whoisoperator*.
   
   See `Wikipedia <http://en.wikipedia.org/wiki/Internet_Relay_Chat>`__ for more
   information about the IRC protocol.
   

   :c: The connection.
   

   :is_orig: True if the command was sent by the originator of the TCP
            connection.
   

   :nick: The nickname specified in the reply.
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message

.. bro:id:: irc_whois_user_line

   :Type: :bro:type:`event` (c: :bro:type:`connection`, is_orig: :bro:type:`bool`, nick: :bro:type:`string`, user: :bro:type:`string`, host: :bro:type:`string`, real_name: :bro:type:`string`)

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
   
   .. bro:see:: irc_channel_info irc_channel_topic irc_dcc_message irc_error_message
      irc_global_users irc_invalid_nick irc_invite_message irc_join_message
      irc_kick_message irc_message irc_mode_message irc_names_info irc_network_info
      irc_nick_message irc_notice_message irc_oper_message irc_oper_response
      irc_part_message irc_password_message


