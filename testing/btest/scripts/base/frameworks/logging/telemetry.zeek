# @TEST-DOC: Check telemetry.log for log stream and log filter writes.
# @TEST-EXEC: zeek -b -r ${TRACES}/wikipedia.trace %INPUT
# @TEST-EXEC: btest-diff telemetry.log

@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http

@load policy/frameworks/telemetry/log

global http_logs = 0;
hook HTTP::log_policy(rec: HTTP::Info, id: Log::ID, filter: Log::Filter)
	{
        if (++http_logs % 3 == 0)
		break;
	}

global dns_logs = 0;
global conn_logs = 0;
hook Log::log_stream_policy(rec: any, id: Log::ID)
	{
        if (id == DNS::LOG && ++dns_logs % 3 == 0)
		break;

        if (id == Conn::LOG && ++conn_logs % 7 == 0)
		break;
	}

hook Telemetry::log_policy(rec: Telemetry::Info, id: Log::ID, filter: Log::Filter)
	{
	if ( (rec?$prefix && rec$prefix != "zeek") || /^zeek_log_/ !in rec$name )
		break;

	if ( /HTTP|DNS|Conn/ !in cat(rec$label_values) )
		break;
	}
