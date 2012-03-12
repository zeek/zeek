##! The input framework provides a way to read previously stored data either
##! as an event stream or into a bro table.

module Input;

export {
         
	redef enum Input::ID += { TABLE_READ };

	## The default input reader used. Defaults to `READER_ASCII`.
	const default_reader = READER_ASCII &redef;

	const default_mode = MANUAL &redef;

	## Stream decription type used for the `create_stream` method
	type StreamDescription: record {
		## String that allows the reader to find the source.
		## For `READER_ASCII`, this is the filename.
		source: string;
		
		## Reader to use for this steam
		reader: Reader &default=default_reader;

		## Read mode to use for this stream
		mode: Mode &default=default_mode;

		## Automatically start the input stream after the first filter has been added
		autostart: bool &default=T;
	};

	## TableFilter description type used for the `add_tablefilter` method.
	type TableFilter: record {
		## Descriptive name. Used to remove a filter at a later time
		name: string; 

		## Table which will contain the data read by the input framework
		destination: any;
		## Record that defines the values used as the index of the table
		idx: any;
		## Record that defines the values used as the values of the table
		## If val is undefined, destination has to be a set.
		val: any &optional;
		## Defines if the value of the table is a record (default), or a single value.
		## Val can only contain one element when this is set to false.
		want_record: bool &default=T;

		## The event that is raised each time a value is added to, changed in or removed from the table.
		## The event will receive an Input::Event enum as the first argument, the idx record as the second argument
		## and the value (record) as the third argument.
		ev: any &optional; # event containing idx, val as values.		

		## Predicate function, that can decide if an insertion, update or removal should really be executed.
		## Parameters are the same as for the event. If true is returned, the update is performed. If false
		## is returned, it is skipped
		pred: function(typ: Input::Event, left: any, right: any): bool &optional;
	};

	## EventFilter description type used for the `add_eventfilter` method.
	type EventFilter: record {
		## Descriptive name. Used to remove a filter at a later time
		name: string;

		## Record describing the fields to be retrieved from the source input.
		fields: any;
		## If want_record if false (default), the event receives each value in fields as a seperate argument.
		## If it is set to true, the event receives all fields in a signle record value.
		want_record: bool &default=F;

		## The event that is rised each time a new line is received from the reader.
		## The event will receive an Input::Event enum as the first element, and the fields as the following arguments.
		ev: any; 

	};

	#const no_filter: Filter = [$name="<not found>", $idx="", $val="", $destination=""]; # Sentinel.

	## Create a new input stream from a given source. Returns true on success.
	##
	## id: `Input::ID` enum value identifying this stream
	## description: `StreamDescription` record describing the source.
	global create_stream: function(id: Input::ID, description: Input::StreamDescription) : bool;

	## Remove a current input stream. Returns true on success.
	##
	## id: `Input::ID` enum value identifying the stream to be removed
	global remove_stream: function(id: Input::ID) : bool;

	## Forces the current input to be checked for changes.
	##
	## id: `Input::ID` enum value identifying the stream
	global force_update: function(id: Input::ID) : bool;

	## Adds a table filter to a specific input stream. Returns true on success.
	##
	## id: `Input::ID` enum value identifying the stream
	## filter: the `TableFilter` record describing the filter.
	global add_tablefilter: function(id: Input::ID, filter: Input::TableFilter) : bool;

	## Removes a named table filter to a specific input stream. Returns true on success.
	##
	## id: `Input::ID` enum value identifying the stream
	## name: the name of the filter to be removed.
	global remove_tablefilter: function(id: Input::ID, name: string) : bool;

	## Adds an event filter to a specific input stream. Returns true on success.
	##
	## id: `Input::ID` enum value identifying the stream
	## filter: the `EventFilter` record describing the filter.
	global add_eventfilter: function(id: Input::ID, filter: Input::EventFilter) : bool;

	## Removes a named event filter to a specific input stream. Returns true on success.
	##
	## id: `Input::ID` enum value identifying the stream
	## name: the name of the filter to be removed.
	global remove_eventfilter: function(id: Input::ID, name: string) : bool;
	#global get_filter: function(id: ID, name: string) : Filter;
	
	## Convenience function for reading a specific input source exactly once using 
	## exactly one tablefilter
	##
	## id: `Input::ID` enum value identifying the stream
	## description: `StreamDescription` record describing the source.
	## filter: the `TableFilter` record describing the filter.	
	global read_table: function(description: Input::StreamDescription, filter: Input::TableFilter) : bool;

	global update_finished: event(id: Input::ID);

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

function add_eventfilter(id: Input::ID, filter: Input::EventFilter) : bool
	{
#	filters[id, filter$name] = filter;
	return __add_eventfilter(id, filter);
	}

function remove_eventfilter(id: Input::ID, name: string) : bool
	{
#	delete filters[id, name];
	return __remove_eventfilter(id, name);
	}

function read_table(description: Input::StreamDescription, filter: Input::TableFilter) : bool {
	local ok: bool = T;
	# since we create and delete it ourselves this should be ok... at least for singlethreaded operation
	local id: Input::ID = Input::TABLE_READ;

	ok = create_stream(id, description);
	if ( ok ) {
		ok = add_tablefilter(id, filter);
	}
	if ( ok ) {
		ok = remove_stream(id);
	} else {
		remove_stream(id);
	}

	return ok;
}

#function get_filter(id: ID, name: string) : Filter
#	{
#	if ( [id, name] in filters )
#		return filters[id, name];
#
#	return no_filter;
#	}
