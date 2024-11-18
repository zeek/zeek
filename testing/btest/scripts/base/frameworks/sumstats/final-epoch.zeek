# @TEST-EXEC: zeek -b %INPUT -r $TRACES/wikipedia.trace
# @TEST-EXEC: TEST_DIFF_CANONIFIER= btest-diff .stdout

@load base/frameworks/sumstats

event connection_state_remove(c: connection)
	{
	print "connection_state_remove", c$uid;
	SumStats::observe("conn",
		[$host=c$id$resp_h],
		[$num=1]
				);
	SumStats::observe("orig_h",
		[$host=c$id$resp_h],
		[$str=cat(c$id$orig_h)]
	);
	}

event zeek_init()
	{
	print "zeek_init";
	SumStats::create([$name = "connections",
		$epoch = 1hr,
		$reducers = set(
			SumStats::Reducer($stream="conn",
				$apply=set(SumStats::SUM),
			),
			SumStats::Reducer($stream="orig_h",
				$apply=set(SumStats::UNIQUE)
			),
		),
		$epoch_finished(ts: time) = {
			print "epoch finished", ts;
		},
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
			print "epoch result";
			print fmt("remote:%s connections:%s orig_unique:%s",
			           key$host,
			           result["conn"]$sum,
			           result["orig_h"]$unique);
		}
	]);
	}

event net_done(ts: time)
	{
	print "net_done", ts;
	}


event zeek_done()
	{
	print "zeek_done";
	}
