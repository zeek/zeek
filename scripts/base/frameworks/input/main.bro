
module Input;

export {
	const default_reader = READER_ASCII &redef;

	type StreamDescription: record {
		source: string;
		reader: Reader &default=default_reader;
	};

	type TableFilter: record {
		## descriptive name. for later removal
		name: string; 

		## for tables
		idx: any;
		val: any;
		destination: any;
		want_record: bool &default=T;
		ev: any &optional; # event containing idx, val as values.		

		## decision function, that decides if an insertion, update or removal should really be executed.
		## or events should be thought
		pred: function(typ: Input::Event, left: any, right: any): bool &optional;
	};

	type EventFilter: record {
		## descriptive name. for later removal
		name: string;

		# the event
		ev: any; 
		# record describing the fields
		fields: any;

		# does the event want the field unrolled (default) or as a simple record value?
		want_record: bool &default=F;
	};

	#const no_filter: Filter = [$name="<not found>", $idx="", $val="", $destination=""]; # Sentinel.

	global create_stream: function(id: Log::ID, description: Input::StreamDescription) : bool;
	global remove_stream: function(id: Log::ID) : bool;
	global force_update: function(id: Log::ID) : bool;
	global add_tablefilter: function(id: Log::ID, filter: Input::TableFilter) : bool;
	global remove_tablefilter: function(id: Log::ID, name: string) : bool;
	global add_eventfilter: function(id: Log::ID, filter: Input::EventFilter) : bool;
	global remove_eventfilter: function(id: Log::ID, name: string) : bool;
	#global get_filter: function(id: ID, name: string) : Filter;

}

@load base/input.bif


module Input;

#global filters: table[ID, string] of Filter;

function create_stream(id: Input::ID, description: Input::StreamDescription) : bool
	{
	return __create_stream(id, description);
	}

function remove_stream(id: Input::ID) : bool
	{
	return __remove_stream(id);
	}

function force_update(id: Input::ID) : bool
	{
	return __force_update(id);
	}

function add_tablefilter(id: Input::ID, filter: Input::TableFilter) : bool
	{
#	filters[id, filter$name] = filter;
	return __add_tablefilter(id, filter);
	}

function remove_tablefilter(id: Input::ID, name: string) : bool
	{
#	delete filters[id, name];
	return __remove_tablefilter(id, name);
	}

function add_eventfilter(id: Log::ID, filter: Input::EventFilter) : bool
	{
#	filters[id, filter$name] = filter;
	return __add_eventfilter(id, filter);
	}

function remove_eventfilter(id: Log::ID, name: string) : bool
	{
#	delete filters[id, name];
	return __remove_eventfilter(id, name);
	}

#function get_filter(id: ID, name: string) : Filter
#	{
#	if ( [id, name] in filters )
#		return filters[id, name];
#
#	return no_filter;
#	}
