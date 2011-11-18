
module Input;

export {
	const default_reader = READER_ASCII &redef;

	type StreamDescription: record {
		source: string;
		reader: Reader &default=default_reader;
	};

	type Filter: record {
		## descriptive name. for later removal
		name: string; 

		## for tables
		idx: any &optional;
		val: any &optional;
		destination: any &optional;
		want_record: bool &default=T;
		table_ev: any &optional; # event containing idx, val as values.		

		## decision function, that decides if an insertion, update or removal should really be executed.
		## or events should be thought
		pred: function(typ: Input::Event, left: any, right: any): bool &optional;

		## for "normalized" events
		ev: any &optional;
		ev_description: any &optional;
	};

	const no_filter: Filter = [$name="<not found>"]; # Sentinel.

	global create_stream: function(id: Log::ID, description: Input::ReaderDescription) : bool;
	global remove_stream: function(id: Log::ID) : bool;
	global force_update: function(id: Log::ID) : bool;
	global add_filter: function(id: Log::ID, filter: Input::Filter) : bool;
	global remove_filter: function(id: Log::ID, name: string) : bool;
	global get_filter: function(id: ID, name: string) : Filter;

}

@load base/input.bif


module Input;

global filters: table[ID, string] of Filter;

function create_stream(id: Log::ID, description: Input::ReaderDescription) : bool
	{
	return __create_stream(id, description);
	}

function remove_stream(id: Log::ID) : bool
	{
	return __remove_stream(id);
	}

function force_update(id: Log::ID) : bool
	{
	return __force_update(id);
	}

function add_filter(id: Log::ID, filter: Input::Filter) : bool
	{
	filters[id, filter$name] = filter;
	return __add_filter(id, filter);
	}

function remove_filter(id: Log::ID, name: string) : bool
	{
	delete filters[id, name];
	return __remove_filter(id, name);
	}

function get_filter(id: ID, name: string) : Filter
	{
	if ( [id, name] in filters )
		return filters[id, name];

	return no_filter;
	}
