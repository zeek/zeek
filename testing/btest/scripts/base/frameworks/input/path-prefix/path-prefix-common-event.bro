# @TEST-IGNORE
#
# This file contains code used by the event-driven path-prefix tests.

redef exit_only_after_terminate = T;

type Val: record {
	ip: addr;
	tag: string;
};

event inputev(description: Input::EventDescription,
	      t: Input::Event, data: Val)
	{
	print data;
	}

event Input::end_of_data(name: string, source: string)
	{
	terminate();
	}
