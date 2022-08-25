# @TEST-EXEC: btest-bg-run zeek zeek -b %INPUT
# @TEST-EXEC: btest-bg-wait 10
# @TEST-EXEC: btest-diff zeek/.stdout
# @TEST-EXEC: btest-diff zeek/config.log

@TEST-START-FILE configfile4
DPD::ignore_violations Analyzer::ANALYZER_SYSLOG
@TEST-END-FILE

@load base/frameworks/config

redef exit_only_after_terminate = T;
redef InputConfig::empty_field = "EMPTY";
redef InputConfig::set_separator = "\t";

type Idx: record {
	option_name: string;
};

type Val: record {
	option_val: string;
};

global currconfig: table[string] of string = table();

event InputConfig::new_value(name: string, source: string, id: string, value: any)
	{
	print id, lookup_ID(id);
	print "---";
	print value;
	print "---";
	Config::set_value(id, value);
	print id, lookup_ID(id);
	print "---";
	}

event Input::end_of_data(name: string, source:string)
	{
	terminate();
	}

event zeek_init()
	{
	Input::add_table([$reader=Input::READER_CONFIG, $source="../configfile4", $name="configuration", $idx=Idx, $val=Val, $destination=currconfig, $want_record=F]);
	}
