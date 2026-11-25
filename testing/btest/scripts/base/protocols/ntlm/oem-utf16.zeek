# @TEST-DOC: An OEM string that a client wrote in UTF-16LE (a NEGOTIATE domain "None").
#
# @TEST-EXEC: zeek -b -r $TRACES/ntlm/oem-utf16.pcap %INPUT >out
# @TEST-EXEC: btest-diff out

@load base/protocols/ntlm
@load base/protocols/smb

event ntlm_negotiate(c: connection, negotiate: NTLM::Negotiate)
	{
	print fmt("%s negotiate domain=%s", c$id$orig_p, negotiate?$domain_name ? negotiate$domain_name : "-");
	}

event conn_weird(name: string, c: connection, addl: string, source: string)
	{
	print fmt("%s weird=%s addl= %s", c$id$orig_p, name, addl);
	}
