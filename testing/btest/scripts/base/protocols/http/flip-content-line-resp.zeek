# @TEST-DOC: Flipping roles of a HTTP connection didn't flip the content line analyzers, resulting in inconsistent deliveries. Regression test for #3789

# Pcap contains a download of the Zeek logo, expecting SHA1 1991cedee47909e324ac1b8bee2020d5690891e1 in files.log
# @TEST-EXEC: zeek -b -r $TRACES/http/zeek-image-1080-80-x.pcap %INPUT
# @TEST-EXEC: zeek-cut -m id.orig_h id.orig_p id.resp_h id.resp_p history service < conn.log > conn.log.cut
# @TEST-EXEC: zeek-cut -m id.orig_h id.orig_p id.resp_h id.resp_p host method uri version user_agent status_code status_msg < http.log > http.log.cut
# @TEST-EXEC: zeek-cut -m id.orig_h id.orig_p id.resp_h id.resp_p analyzers mime_type sha1 < files.log > files.log.cut
# @TEST-EXEC: btest-diff conn.log.cut
# @TEST-EXEC: btest-diff http.log.cut
# @TEST-EXEC: btest-diff files.log.cut

@load base/protocols/conn
@load base/protocols/http
@load base/files/hash

event file_new(f: fa_file)
	{
	Files::add_analyzer(f, Files::ANALYZER_SHA1);
	}
