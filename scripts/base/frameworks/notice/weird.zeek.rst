:tocdepth: 3

base/frameworks/notice/weird.zeek
=================================
.. zeek:namespace:: Weird

This script provides a default set of actions to take for "weird activity"
events generated from Zeek's event engine.  Weird activity is defined as
unusual or exceptional activity that can indicate malformed connections,
traffic that doesn't conform to a particular protocol, malfunctioning
or misconfigured hardware, or even an attacker attempting to avoid/confuse
a sensor.  Without context, it's hard to judge whether a particular
category of weird activity is interesting, but this script provides
a starting point for the user.

:Namespace: Weird
:Imports: :doc:`base/frameworks/notice/main.zeek </scripts/base/frameworks/notice/main.zeek>`, :doc:`base/utils/conn-ids.zeek </scripts/base/utils/conn-ids.zeek>`, :doc:`base/utils/site.zeek </scripts/base/utils/site.zeek>`

Summary
~~~~~~~
Runtime Options
###############
=================================================================================== ==============================================================
:zeek:id:`Weird::ignore_hosts`: :zeek:type:`set` :zeek:attr:`&redef`                To completely ignore a specific weird for a host, add the host
                                                                                    and weird name into this set.
:zeek:id:`Weird::weird_do_not_ignore_repeats`: :zeek:type:`set` :zeek:attr:`&redef` Don't ignore repeats for weirds in this set.
=================================================================================== ==============================================================

Redefinable Options
###################
=============================================================================================================== ==============================================================
:zeek:id:`Weird::actions`: :zeek:type:`table` :zeek:attr:`&default` = ``Weird::ACTION_LOG`` :zeek:attr:`&redef` A table specifying default/recommended actions per weird type.
=============================================================================================================== ==============================================================

State Variables
###############
================================================================================================================ ====================================================================
:zeek:id:`Weird::did_log`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`        A state set which tracks unique weirds solely by name to reduce
                                                                                                                 duplicate logging.
:zeek:id:`Weird::did_notice`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`     A state set which tracks unique weirds solely by name to reduce
                                                                                                                 duplicate notices from being raised.
:zeek:id:`Weird::weird_ignore`: :zeek:type:`set` :zeek:attr:`&create_expire` = ``10.0 mins`` :zeek:attr:`&redef` This table is used to track identifier and name pairs that should be
                                                                                                                 temporarily ignored because the problem has already been reported.
================================================================================================================ ====================================================================

Types
#####
============================================= =======================================================================
:zeek:type:`Weird::Action`: :zeek:type:`enum` Types of actions that may be taken when handling weird activity events.
:zeek:type:`Weird::Info`: :zeek:type:`record` The record which is used for representing and logging weirds.
============================================= =======================================================================

Redefinitions
#############
============================================ ====================================
:zeek:type:`Log::ID`: :zeek:type:`enum`      The weird logging stream identifier.
:zeek:type:`Notice::Type`: :zeek:type:`enum` 
============================================ ====================================

Events
######
=============================================== ==============================================================
:zeek:id:`Weird::log_weird`: :zeek:type:`event` Handlers of this event are invoked once per write to the weird
                                                logging stream before the data is actually written.
=============================================== ==============================================================

Functions
#########
============================================== =
:zeek:id:`Weird::weird`: :zeek:type:`function` 
============================================== =


Detailed Interface
~~~~~~~~~~~~~~~~~~
Runtime Options
###############
.. zeek:id:: Weird::ignore_hosts

   :Type: :zeek:type:`set` [:zeek:type:`addr`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default: ``{}``

   To completely ignore a specific weird for a host, add the host
   and weird name into this set.

.. zeek:id:: Weird::weird_do_not_ignore_repeats

   :Type: :zeek:type:`set` [:zeek:type:`string`]
   :Attributes: :zeek:attr:`&redef`
   :Default:

      ::

         {
            "bad_ICMP_checksum",
            "bad_TCP_checksum",
            "bad_IP_checksum",
            "bad_UDP_checksum"
         }


   Don't ignore repeats for weirds in this set.  For example,
   it's handy keeping track of clustered checksum errors.

Redefinable Options
###################
.. zeek:id:: Weird::actions

   :Type: :zeek:type:`table` [:zeek:type:`string`] of :zeek:type:`Weird::Action`
   :Attributes: :zeek:attr:`&default` = ``Weird::ACTION_LOG`` :zeek:attr:`&redef`
   :Default:

      ::

         {
            ["DNS_AAAA_neg_length"] = Weird::ACTION_LOG,
            ["partial_ftp_request"] = Weird::ACTION_LOG,
            ["repeated_SYN_reply_wo_ack"] = Weird::ACTION_LOG,
            ["bad_UDP_checksum"] = Weird::ACTION_LOG_PER_ORIG,
            ["line_terminated_with_single_LF"] = Weird::ACTION_LOG,
            ["truncated_IP"] = Weird::ACTION_LOG,
            ["DNS_truncated_len_lt_hdr_len"] = Weird::ACTION_LOG,
            ["excessive_data_without_further_acks"] = Weird::ACTION_LOG,
            ["pop3_malformed_auth_plain"] = Weird::ACTION_LOG,
            ["excess_netbios_hdr_len"] = Weird::ACTION_LOG,
            ["irc_invalid_whois_channel_line"] = Weird::ACTION_LOG,
            ["bad_RPC"] = Weird::ACTION_LOG_PER_ORIG,
            ["unknown_netbios_type"] = Weird::ACTION_LOG,
            ["HTTP_chunked_transfer_for_multipart_message"] = Weird::ACTION_LOG,
            ["RST_storm"] = Weird::ACTION_LOG,
            ["bad_IP_checksum"] = Weird::ACTION_LOG_PER_ORIG,
            ["excessively_small_fragment"] = Weird::ACTION_LOG_PER_ORIG,
            ["bad_rsh_prolog"] = Weird::ACTION_LOG,
            ["pop3_client_sending_server_commands"] = Weird::ACTION_LOG,
            ["unexpected_multiple_HTTP_requests"] = Weird::ACTION_LOG,
            ["irc_invalid_topic_reply"] = Weird::ACTION_LOG,
            ["irc_invalid_squery_message_format"] = Weird::ACTION_LOG,
            ["bad_SYN_ack"] = Weird::ACTION_LOG,
            ["contentline_size_exceeded"] = Weird::ACTION_LOG,
            ["above_hole_data_without_any_acks"] = Weird::ACTION_LOG,
            ["bad_HTTP_reply"] = Weird::ACTION_LOG,
            ["DNS_RR_length_mismatch"] = Weird::ACTION_LOG,
            ["SMB_parsing_error"] = Weird::ACTION_LOG,
            ["multiple_HTTP_request_elements"] = Weird::ACTION_LOG,
            ["FIN_after_reset"] = Weird::ACTION_IGNORE,
            ["SYN_after_partial"] = Weird::ACTION_NOTICE_PER_ORIG,
            ["baroque_SYN"] = Weird::ACTION_LOG,
            ["DNS_label_forward_compress_offset"] = Weird::ACTION_LOG_PER_ORIG,
            ["connection_originator_SYN_ack"] = Weird::ACTION_LOG_PER_ORIG,
            ["irc_invalid_dcc_message_format"] = Weird::ACTION_LOG,
            ["unmatched_HTTP_reply"] = Weird::ACTION_LOG,
            ["unpaired_RPC_response"] = Weird::ACTION_LOG,
            ["SYN_inside_connection"] = Weird::ACTION_LOG,
            ["irc_invalid_who_message_format"] = Weird::ACTION_LOG,
            ["irc_invalid_reply_number"] = Weird::ACTION_LOG,
            ["pop3_client_command_unknown"] = Weird::ACTION_LOG,
            ["bad_ICMP_checksum"] = Weird::ACTION_LOG_PER_ORIG,
            ["DNS_RR_unknown_type"] = Weird::ACTION_LOG,
            ["excessively_large_fragment"] = Weird::ACTION_LOG,
            ["DNS_label_len_gt_name_len"] = Weird::ACTION_LOG_PER_ORIG,
            ["DNS_label_len_gt_pkt"] = Weird::ACTION_LOG_PER_ORIG,
            ["partial_ident_request"] = Weird::ACTION_LOG,
            ["excess_RPC"] = Weird::ACTION_LOG_PER_ORIG,
            ["line_terminated_with_single_CR"] = Weird::ACTION_LOG,
            ["unknown_HTTP_method"] = Weird::ACTION_LOG,
            ["bad_ident_request"] = Weird::ACTION_LOG,
            ["crud_trailing_HTTP_request"] = Weird::ACTION_LOG,
            ["irc_invalid_whois_operator_line"] = Weird::ACTION_LOG,
            ["unexpected_server_HTTP_data"] = Weird::ACTION_LOG,
            ["irc_invalid_njoin_line"] = Weird::ACTION_LOG,
            ["irc_invalid_mode_message_format"] = Weird::ACTION_LOG,
            ["pop3_bad_base64_encoding"] = Weird::ACTION_LOG,
            ["responder_RPC_call"] = Weird::ACTION_LOG_PER_ORIG,
            ["fragment_size_inconsistency"] = Weird::ACTION_LOG_PER_ORIG,
            ["successful_RPC_reply_to_invalid_request"] = Weird::ACTION_NOTICE_PER_ORIG,
            ["irc_line_too_short"] = Weird::ACTION_LOG,
            ["irc_invalid_kick_message_format"] = Weird::ACTION_LOG,
            ["repeated_SYN_with_ack"] = Weird::ACTION_LOG,
            ["partial_finger_request"] = Weird::ACTION_LOG,
            ["irc_invalid_join_line"] = Weird::ACTION_LOG,
            ["premature_connection_reuse"] = Weird::ACTION_LOG,
            ["netbios_raw_session_msg"] = Weird::ACTION_LOG,
            ["incompletely_captured_fragment"] = Weird::ACTION_LOG,
            ["malformed_ssh_version"] = Weird::ACTION_LOG,
            ["netbios_client_session_reply"] = Weird::ACTION_LOG,
            ["bad_TCP_header_len"] = Weird::ACTION_LOG,
            ["unescaped_%_in_URI"] = Weird::ACTION_LOG,
            ["netbios_server_session_request"] = Weird::ACTION_LOG,
            ["irc_too_many_invalid"] = Weird::ACTION_LOG,
            ["irc_invalid_names_line"] = Weird::ACTION_LOG,
            ["RPC_rexmit_inconsistency"] = Weird::ACTION_LOG,
            ["smb_andx_command_failed_to_parse"] = Weird::ACTION_LOG,
            ["irc_invalid_invite_message_format"] = Weird::ACTION_LOG,
            ["spontaneous_FIN"] = Weird::ACTION_IGNORE,
            ["DNS_truncated_quest_too_short"] = Weird::ACTION_LOG,
            ["SSL_many_server_names"] = Weird::ACTION_LOG,
            ["FIN_storm"] = Weird::ACTION_NOTICE_PER_ORIG,
            ["data_before_established"] = Weird::ACTION_LOG,
            ["SYN_after_reset"] = Weird::ACTION_LOG,
            ["double_%_in_URI"] = Weird::ACTION_LOG,
            ["DNS_truncated_ans_too_short"] = Weird::ACTION_LOG,
            ["DNS_Conn_count_too_large"] = Weird::ACTION_LOG,
            ["data_after_reset"] = Weird::ACTION_LOG,
            ["RPC_underflow"] = Weird::ACTION_LOG,
            ["unexpected_client_HTTP_data"] = Weird::ACTION_LOG,
            ["originator_RPC_reply"] = Weird::ACTION_LOG_PER_ORIG,
            ["DNS_label_too_long"] = Weird::ACTION_LOG_PER_ORIG,
            ["SYN_with_data"] = Weird::ACTION_LOG_PER_ORIG,
            ["RST_with_data"] = Weird::ACTION_LOG,
            ["bad_HTTP_version"] = Weird::ACTION_LOG,
            ["pending_data_when_closed"] = Weird::ACTION_LOG,
            ["rlogin_text_after_rejected"] = Weird::ACTION_LOG,
            ["FIN_advanced_last_seq"] = Weird::ACTION_LOG,
            ["transaction_subcmd_missing"] = Weird::ACTION_LOG,
            ["fragment_protocol_inconsistency"] = Weird::ACTION_LOG,
            ["invalid_irc_global_users_reply"] = Weird::ACTION_LOG,
            ["ident_request_addendum"] = Weird::ACTION_LOG,
            ["window_recision"] = Weird::ACTION_LOG,
            ["spontaneous_RST"] = Weird::ACTION_IGNORE,
            ["truncated_header"] = Weird::ACTION_LOG,
            ["UDP_datagram_length_mismatch"] = Weird::ACTION_LOG_PER_ORIG,
            ["fragment_with_DF"] = Weird::ACTION_LOG,
            ["SYN_after_close"] = Weird::ACTION_LOG,
            ["SYN_seq_jump"] = Weird::ACTION_LOG,
            ["irc_invalid_notice_message_format"] = Weird::ACTION_LOG,
            ["irc_invalid_command"] = Weird::ACTION_LOG,
            ["DNS_NAME_too_long"] = Weird::ACTION_LOG,
            ["inflate_failed"] = Weird::ACTION_LOG,
            ["base64_illegal_encoding"] = Weird::ACTION_LOG,
            ["internally_truncated_header"] = Weird::ACTION_LOG,
            ["pop3_server_sending_client_commands"] = Weird::ACTION_LOG,
            ["irc_invalid_who_line"] = Weird::ACTION_LOG,
            ["irc_invalid_privmsg_message_format"] = Weird::ACTION_LOG,
            ["pop3_server_command_unknown"] = Weird::ACTION_LOG,
            ["fragment_overlap"] = Weird::ACTION_LOG_PER_ORIG,
            ["bad_rlogin_prolog"] = Weird::ACTION_LOG,
            ["bad_ident_port"] = Weird::ACTION_LOG,
            ["irc_invalid_line"] = Weird::ACTION_LOG,
            ["HTTP_overlapping_messages"] = Weird::ACTION_LOG,
            ["simultaneous_open"] = Weird::ACTION_LOG_PER_CONN,
            ["unsolicited_SYN_response"] = Weird::ACTION_IGNORE,
            ["DNS_RR_bad_length"] = Weird::ACTION_LOG,
            ["TCP_christmas"] = Weird::ACTION_LOG,
            ["inappropriate_FIN"] = Weird::ACTION_LOG,
            ["irc_invalid_oper_message_format"] = Weird::ACTION_LOG,
            ["no_smb_session_using_parsesambamsg"] = Weird::ACTION_LOG,
            ["illegal_%_at_end_of_URI"] = Weird::ACTION_LOG,
            ["active_connection_reuse"] = Weird::ACTION_LOG,
            ["bad_TCP_checksum"] = Weird::ACTION_LOG_PER_ORIG,
            ["fragment_inconsistency"] = Weird::ACTION_LOG_PER_ORIG,
            ["malformed_ssh_identification"] = Weird::ACTION_LOG,
            ["DNS_truncated_RR_rdlength_lt_len"] = Weird::ACTION_LOG,
            ["possible_split_routing"] = Weird::ACTION_LOG,
            ["irc_line_size_exceeded"] = Weird::ACTION_LOG,
            ["bad_RPC_program"] = Weird::ACTION_LOG,
            ["bad_ident_reply"] = Weird::ACTION_LOG,
            ["HTTP_bad_chunk_size"] = Weird::ACTION_LOG,
            ["unescaped_special_URI_char"] = Weird::ACTION_LOG,
            ["HTTP_version_mismatch"] = Weird::ACTION_LOG,
            ["irc_invalid_whois_message_format"] = Weird::ACTION_LOG,
            ["rsh_text_after_rejected"] = Weird::ACTION_LOG,
            ["partial_RPC"] = Weird::ACTION_LOG_PER_ORIG,
            ["truncated_ARP"] = Weird::ACTION_LOG,
            ["truncated_NTP"] = Weird::ACTION_LOG,
            ["irc_invalid_whois_user_line"] = Weird::ACTION_LOG,
            ["NUL_in_line"] = Weird::ACTION_LOG,
            ["deficit_netbios_hdr_len"] = Weird::ACTION_LOG
         }


   A table specifying default/recommended actions per weird type.

State Variables
###############
.. zeek:id:: Weird::did_log

   :Type: :zeek:type:`set` [:zeek:type:`string`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`
   :Default: ``{}``

   A state set which tracks unique weirds solely by name to reduce
   duplicate logging.  This is deliberately not synchronized because it
   could cause overload during storms.

.. zeek:id:: Weird::did_notice

   :Type: :zeek:type:`set` [:zeek:type:`string`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&create_expire` = ``1.0 day`` :zeek:attr:`&redef`
   :Default: ``{}``

   A state set which tracks unique weirds solely by name to reduce
   duplicate notices from being raised.

.. zeek:id:: Weird::weird_ignore

   :Type: :zeek:type:`set` [:zeek:type:`string`, :zeek:type:`string`]
   :Attributes: :zeek:attr:`&create_expire` = ``10.0 mins`` :zeek:attr:`&redef`
   :Default: ``{}``

   This table is used to track identifier and name pairs that should be
   temporarily ignored because the problem has already been reported.
   This helps reduce the volume of high volume weirds by only allowing 
   a unique weird every ``create_expire`` interval.

Types
#####
.. zeek:type:: Weird::Action

   :Type: :zeek:type:`enum`

      .. zeek:enum:: Weird::ACTION_UNSPECIFIED Weird::Action

         A dummy action indicating the user does not care what
         internal decision is made regarding a given type of weird.

      .. zeek:enum:: Weird::ACTION_IGNORE Weird::Action

         No action is to be taken.

      .. zeek:enum:: Weird::ACTION_LOG Weird::Action

         Log the weird event every time it occurs.

      .. zeek:enum:: Weird::ACTION_LOG_ONCE Weird::Action

         Log the weird event only once.

      .. zeek:enum:: Weird::ACTION_LOG_PER_CONN Weird::Action

         Log the weird event once per connection.

      .. zeek:enum:: Weird::ACTION_LOG_PER_ORIG Weird::Action

         Log the weird event once per originator host.

      .. zeek:enum:: Weird::ACTION_NOTICE Weird::Action

         Always generate a notice associated with the weird event.

      .. zeek:enum:: Weird::ACTION_NOTICE_ONCE Weird::Action

         Generate a notice associated with the weird event only once.

      .. zeek:enum:: Weird::ACTION_NOTICE_PER_CONN Weird::Action

         Generate a notice for the weird event once per connection.

      .. zeek:enum:: Weird::ACTION_NOTICE_PER_ORIG Weird::Action

         Generate a notice for the weird event once per originator host.

   Types of actions that may be taken when handling weird activity events.

.. zeek:type:: Weird::Info

   :Type: :zeek:type:`record`

      ts: :zeek:type:`time` :zeek:attr:`&log`
         The time when the weird occurred.

      uid: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         If a connection is associated with this weird, this will be
         the connection's unique ID.

      id: :zeek:type:`conn_id` :zeek:attr:`&log` :zeek:attr:`&optional`
         conn_id for the optional connection.

      conn: :zeek:type:`connection` :zeek:attr:`&optional`
         A shorthand way of giving the uid and id to a weird.

      name: :zeek:type:`string` :zeek:attr:`&log`
         The name of the weird that occurred.

      addl: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional`
         Additional information accompanying the weird if any.

      notice: :zeek:type:`bool` :zeek:attr:`&log` :zeek:attr:`&default` = ``F`` :zeek:attr:`&optional`
         Indicate if this weird was also turned into a notice.

      peer: :zeek:type:`string` :zeek:attr:`&log` :zeek:attr:`&optional` :zeek:attr:`&default` = :zeek:see:`peer_description`
         The peer that originated this weird.  This is helpful in
         cluster deployments if a particular cluster node is having
         trouble to help identify which node is having trouble.

      identifier: :zeek:type:`string` :zeek:attr:`&optional`
         This field is to be provided when a weird is generated for
         the purpose of deduplicating weirds. The identifier string
         should be unique for a single instance of the weird. This field
         is used to define when a weird is conceptually a duplicate of
         a previous weird.

   The record which is used for representing and logging weirds.

Events
######
.. zeek:id:: Weird::log_weird

   :Type: :zeek:type:`event` (rec: :zeek:type:`Weird::Info`)

   Handlers of this event are invoked once per write to the weird
   logging stream before the data is actually written.
   

   :rec: The weird columns about to be logged to the weird stream.

Functions
#########
.. zeek:id:: Weird::weird

   :Type: :zeek:type:`function` (w: :zeek:type:`Weird::Info`) : :zeek:type:`void`



