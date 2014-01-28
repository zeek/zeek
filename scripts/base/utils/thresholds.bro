##! Functions for using multiple thresholds with a counting tracker.  For
##! example, you may want to generate a notice when something happens 10 times
##! and again when it happens 100 times but nothing in between.  You can use
##! the :bro:id:`check_threshold` function to define your threshold points
##! and the :bro:type:`TrackCount` variable where you are keeping track of your
##! counter.

module GLOBAL;

export {
	type TrackCount: record {
		## The counter for the number of times something has happened.
		n:     count &default=0;
		## The index of the vector where the counter currently is.  This
		## is used to track which threshold is currently being watched
		## for.
		index: count &default=0;
	};
	
	## The thresholds you would like to use as defaults with the 
	## :bro:id:`default_check_threshold` function.
	const default_notice_thresholds: vector of count = {
		30, 100, 1000, 10000, 100000, 1000000, 10000000,
	} &redef;
	
	## This will check if a :bro:type:`TrackCount` variable has crossed any
	## thresholds in a given set.
	##
	## v: a vector holding counts that represent thresholds.
	##
	## tracker: the record being used to track event counter and currently
	##          monitored threshold value.
	##
	## Returns: T if a threshold has been crossed, else F.
	global check_threshold: function(v: vector of count, tracker: TrackCount): bool;
	
	## This will use the :bro:id:`default_notice_thresholds` variable to
	## check a :bro:type:`TrackCount` variable to see if it has crossed
	## another threshold.
	global default_check_threshold: function(tracker: TrackCount): bool;
}

function new_track_count(): TrackCount
	{
	local tc: TrackCount;
	return tc;
	}

function check_threshold(v: vector of count, tracker: TrackCount): bool
	{
	if ( tracker$index <= |v| && tracker$n >= v[tracker$index] )
		{
		++tracker$index;
		return T;
		}
	return F;
	}

function default_check_threshold(tracker: TrackCount): bool
	{
	return check_threshold(default_notice_thresholds, tracker);
	}
