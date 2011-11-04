
module Input;

export {
	const default_reader = READER_ASCII &redef;

	type ReaderDescription: record {
		source: string;
		idx: any;
		val: any;
		destination: any;
		reader: Reader &default=default_reader;
	};

	type Filter: record {
		name: string; 
		## descriptive name. for later removal

		pred: function(typ: Input::Event, left: any, right: any): bool &optional;
		## decision function, that decides if an inserton, update or removal should really be executed
	};

	const no_filter: Filter = [$name="<not found>"]; # Sentinel.

	global create_reader: function(id: Log::ID, description: Input::ReaderDescription) : bool;
	global remove_reader: function(id: Log::ID) : bool;
	global force_update: function(id: Log::ID) : bool;
	global add_event: function(id: Log::ID, name: string) : bool;
	global remove_event: function(id: Log::ID, name: string) : bool;
	global add_filter: function(id: Log::ID, filter: Input::Filter) : bool;
	global remove_filter: function(id: Log::ID, name: string) : bool;
	global get_filter: function(id: ID, name: string) : Filter;

}

@load base/input.bif


module Input;

global filters: table[ID, string] of Filter;

function create_reader(id: Log::ID, description: Input::ReaderDescription) : bool
	{
	return __create_reader(id, description);
	}

function remove_reader(id: Log::ID) : bool
	{
	return __remove_reader(id);
	}

function force_update(id: Log::ID) : bool
	{
	return __force_update(id);
	}

function add_event(id: Log::ID, name: string) : bool
	{
	return __add_event(id, name);
	}

function remove_event(id: Log::ID, name: string) : bool
	{
	return __remove_event(id, name);
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
