@load base/protocols/conn

redef record Conn::Info += {
	orig_name: string &log &optional;
	resp_name: string &log &optional;
};

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	if ( id != Conn::LOG )
		return;

	local token1 = Log::delay(id, rec);
	local token2 = Log::delay(id, rec);

	when [id, rec, token1] ( local orig_name = lookup_addr(rec$id$orig_h) )
		{
		rec$orig_name = orig_name;
		Log::delay_finish(id, rec, token1);
		}
	timeout 150msec
		{
		Reporter::warning(fmt("lookup_addr timeout for %s", rec$id$orig_h));
		Log::delay_finish(id, rec, token1);
		}

	when [id, rec, token2] ( local resp_name = lookup_addr(rec$id$resp_h) )
		{
		rec$resp_name = resp_name;
		Log::delay_finish(id, rec, token2);
		}
	timeout 150msec
		{
		Reporter::warning(fmt("lookup_addr timeout for %s", rec$id$resp_h));
		Log::delay_finish(id, rec, token2);
		}
	}
