# @TEST-EXEC: zeek -b -s myftp -r $TRACES/ftp/ipv4.trace %INPUT >dpd-ipv4.out
# @TEST-EXEC: zeek -b -s myftp -r $TRACES/ftp/ipv6.trace %INPUT >dpd-ipv6.out
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv4.trace %INPUT >nosig-ipv4.out
# @TEST-EXEC: zeek -b -r $TRACES/ftp/ipv6.trace %INPUT >nosig-ipv6.out
# @TEST-EXEC: btest-diff dpd-ipv4.out
# @TEST-EXEC: btest-diff dpd-ipv6.out
# @TEST-EXEC: btest-diff nosig-ipv4.out
# @TEST-EXEC: btest-diff nosig-ipv6.out

# DPD based on 'ip-proto' and 'payload' signatures should be independent
# of IP protocol.

@TEST-START-FILE myftp.sig
signature my_ftp_client {
  ip-proto == tcp
  payload /(|.*[\n\r]) *[uU][sS][eE][rR] /
  tcp-state originator
  event "matched my_ftp_client"
}

signature my_ftp_server {
  ip-proto == tcp
  payload /[\n\r ]*(120|220)[^0-9].*[\n\r] *(230|331)[^0-9]/
  tcp-state responder
  requires-reverse-signature my_ftp_client
  enable "ftp"
  event "matched my_ftp_server"
}
@TEST-END-FILE

@load base/utils/addrs

event zeek_init()
	{
	# no analyzer attached to any port by default, depends entirely on sigs
	print "|Analyzer::all_registered_ports()|", |Analyzer::all_registered_ports()|;
	}

event signature_match(state: signature_state, msg: string, data: string)
	{
	print fmt("signature_match %s - %s", state$conn$id, msg);
	}

event ftp_request(c: connection, command: string, arg: string)
	{
	print fmt("ftp_request %s:%s - %s %s", addr_to_uri(c$id$orig_h),
	          port_to_count(c$id$orig_p), command, arg);
	}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool)
	{
	print fmt("ftp_reply %s:%s - %s %s", addr_to_uri(c$id$resp_h),
	          port_to_count(c$id$resp_p), code, msg);
	}
