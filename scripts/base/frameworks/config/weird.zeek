##! This script sets up the config framework change handlers for weirds.

@load ./main

module Config;

function weird_option_change_sampling_whitelist(ID: string, new_value: string_set, location: string) : string_set
	{
	if ( ID == "Weird::sampling_whitelist" )
		{
		Reporter::set_weird_sampling_whitelist(new_value);
		}
	return new_value;
	}

function weird_option_change_count(ID: string, new_value: count, location: string) : count
	{
	if ( ID == "Weird::sampling_threshold" )
		{
		Reporter::set_weird_sampling_threshold(new_value);
		}
	else if ( ID == "Weird::sampling_rate" )
		{
		Reporter::set_weird_sampling_rate(new_value);
		}
	return new_value;
	}

function weird_option_change_interval(ID: string, new_value: interval, location: string) : interval
	{
	if ( ID == "Weird::sampling_duration" )
		{
		Reporter::set_weird_sampling_duration(new_value);
		}
	return new_value;
	}

event zeek_init() &priority=5
	{
	Option::set_change_handler("Weird::sampling_whitelist", weird_option_change_sampling_whitelist, 5);
	Option::set_change_handler("Weird::sampling_threshold", weird_option_change_count, 5);
	Option::set_change_handler("Weird::sampling_rate", weird_option_change_count, 5);
	Option::set_change_handler("Weird::sampling_duration", weird_option_change_interval, 5);
	}
