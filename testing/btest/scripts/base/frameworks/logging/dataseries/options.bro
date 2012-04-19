#
# @TEST-REQUIRES: has-writer DataSeries && which ds2txt
# @TEST-GROUP: dataseries
#
# @TEST-EXEC: bro -b %INPUT Log::default_writer=Log::WRITER_DATASERIES
# @TEST-EXEC: test -e ssh.ds.xml
# @TEST-EXEC: btest-diff ssh.ds.xml

module SSH;

redef LogDataSeries::dump_schema = T;

# Haven't yet found a way to check for the effect of these.
redef LogDataSeries::compression = "bz2";
redef LogDataSeries::extent_size = 1000;
redef LogDataSeries::num_threads = 5;

# LogDataSeries::use_integer_for_time is tested separately.

export {
	redef enum Log::ID += { LOG };

	type Log: record {
		t: time;
		id: conn_id; # Will be rolled out into individual columns.
		status: string &optional;
		country: string &default="unknown";
	} &log;
}

event bro_init()
{
	Log::create_stream(SSH::LOG, [$columns=Log]);

    local cid = [$orig_h=1.2.3.4, $orig_p=1234/tcp, $resp_h=2.3.4.5, $resp_p=80/tcp];

	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="US"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="UK"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="success", $country="BR"]);
	Log::write(SSH::LOG, [$t=network_time(), $id=cid, $status="failure", $country="MX"]);
	
}

