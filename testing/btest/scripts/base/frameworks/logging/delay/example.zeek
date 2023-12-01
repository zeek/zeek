# @TEST-DOC: Example using lookup_addr()

# @TEST-EXEC: zeek -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout
# @TEST-EXEC: btest-diff .stderr
# @TEST-EXEC: zeek-cut -m ts uid id.orig_h orig_name id.resp_h resp_name < conn.log > conn.cut
# @TEST-EXEC: btest-diff conn.cut


# Enrich conn.log with lookup_addr() result
@load base/protocols/conn

redef record Conn::Info += {
	orig_name: string &log &optional;
	resp_name: string &log &optional;
};

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	if ( id != Conn::LOG )
		return;

	print network_time(), "log_stream_policy", id, rec;

	local token1 = Log::delay(id, rec, function(rec2: Conn::Info, id2: Log::ID): bool {
		print network_time(), "token1 delay hook";
		return T;
	});
	local token2 = Log::delay(id, rec, function(rec2: Conn::Info, id2: Log::ID): bool {
		print network_time(), "token2 delay hook";
		return T;
	});

	when [id, rec, token1] ( local orig_name = lookup_addr(rec$id$orig_h) )
		{
		rec$orig_name = orig_name;
		Log::delay_finish(id, rec, token1);
		}
	timeout 150msec
		{
		Reporter::warning(fmt("lookup_addr timeout for %s", rec$id$orig_h));
		}

	when [id, rec, token2] ( local resp_name = lookup_addr(rec$id$resp_h) )
		{
		rec$resp_name = resp_name;
		Log::delay_finish(id, rec, token2);
		}
	timeout 150msec
		{
		Reporter::warning(fmt("lookup_addr timeout for %s", rec$id$resp_h));
		}
	}

event Pcap::file_done(path: string)
	{
	print network_time(), "Pcap::file_done";
	}
