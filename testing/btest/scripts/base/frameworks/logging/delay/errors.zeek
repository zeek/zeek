# @TEST-DOC: Test some error cases

# @TEST-EXEC: zeek  -b -r $TRACES/http/get.trace %INPUT
# @TEST-EXEC: TEST_DIFF_CANONIFIER='$SCRIPTS/diff-remove-abspath | sed -r "s/0x[0-9a-z]+/0x<...>/g"' btest-diff .stderr

redef enum Log::ID += { LOG };

event zeek_init()
	{
	# Not within a log write
	Log::delay(LOG, []);
	}

@TEST-START-NEXT
@load base/protocols/conn

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	# Not the same record as the one from the hook.
	Log::delay(id, copy(rec));
	}

@TEST-START-NEXT
@load base/protocols/conn
@load base/protocols/dns

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	# Wrong stream identifier
	Log::delay(DNS::LOG, rec);
	}

@TEST-START-NEXT
@load base/protocols/conn

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	# Wrong record for delay_finish()
	local token = Log::delay(id, rec);
	Log::delay_finish(id, copy(rec), token);
	}

@TEST-START-NEXT
@load base/protocols/conn

hook Log::log_stream_policy(rec: Conn::Info, id: Log::ID)
	{
	# Delay underflow.
	local token = Log::delay(id, rec);
	Log::delay_finish(id, rec, token);
	Log::delay_finish(id, rec, token);
	}
