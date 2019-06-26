# @TEST-IGNORE
#
# This file contains code used by the intel framework path-prefix tests.

@load base/frameworks/intel

redef exit_only_after_terminate = T;

module Intel;

event Intel::new_item(item: Intel::Item)
	{
	print fmt("%s %s", item$indicator, item$indicator_type);
	}

event Input::end_of_data(name: string, source: string)
	{
	terminate();
	}
