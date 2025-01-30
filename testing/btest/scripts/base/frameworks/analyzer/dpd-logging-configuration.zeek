# @TEST-DOC: Check if DPD options on violations work.
# @TEST-EXEC: zeek -r $TRACES/ftp/ftp-invalid-reply-code.pcap %INPUT
# @TEST-EXEC: btest-diff conn.log

@load policy/protocols/conn/failed-services

redef DPD::track_removed_services_in_connection = T;
