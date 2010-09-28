# $Id: cluster-addrs.smtp-relay.bro 6811 2009-07-06 20:41:10Z robin $

redef smtp_relay_table &persistent &synchronized;
redef smtp_session_by_recipient &persistent &synchronized;
redef smtp_session_by_message_id &persistent &synchronized;
redef smtp_session_by_content_hash &persistent &synchronized;
