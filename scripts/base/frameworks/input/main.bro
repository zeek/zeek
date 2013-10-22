##! The input framework provides a way to read previously stored data either
##! as an event stream or into a bro table.

module Input;

export {

	## The default input reader used. Defaults to `READER_ASCII`.
	const default_reader = READER_ASCII &redef;

	## The default reader mode used. Defaults to `MANUAL`.
	const default_mode = MANUAL &redef;

	## Separator between fields.
	## Please note that the separator has to be exactly one character long.
	## Can be overwritten by individual writers.
	const separator = "\t" &redef;

	## Separator between set elements.
	## Please note that the separator has to be exactly one character long.
	## Can be overwritten by individual writers.
	const set_separator = "," &redef;

	## String to use for empty fields.
	## Can be overwritten by individual writers.
	const empty_field = "(empty)" &redef;

	## String to use for an unset &optional field.
	## Can be overwritten by individual writers.
	const unset_field = "-" &redef;

	## Flag that controls if the input framework accepts records
	## that contain types that are not supported (at the moment
	## file and function). If true, the input framework will
	## warn in these cases, but continue. If false, it will
	## abort. Defaults to false (abort).
	const accept_unsupported_types = F &redef;

	## TableFilter description type used for the `table` method.
	type TableDescription: record {
		# Common definitions for tables and events

		## String that allows the reader to find the source.
		## For `READER_ASCII`, this is the filename.
		source: string;

		## Reader to use for this stream.
		reader: Reader &default=default_reader;

		## Read mode to use for this stream.
		mode: Mode &default=default_mode;

		## Descriptive name. Used to remove a stream at a later time.
		name: string;

		# Special definitions for tables

		## Table which will receive the data read by the input framework.
		destination: any;

		## Record that defines the values used as the index of the table.
		idx: any;

		## Record that defines the values used as the elements of the table.
		## If this is undefined, then *destination* has to be a set.
		val: any &optional;

		## Defines if the value of the table is a record (default), or a single value.
		## When this is set to false, then *val* can only contain one element.
		want_record: bool &default=T;

		## The event that is raised each time a value is added to, changed in or removed
		## from the table. The event will receive an Input::Event enum as the first
		## argument, the *idx* record as the second argument and the value (record) as the
		## third argument.
		ev: any &optional; # event containing idx, val as values.

		## Predicate function that can decide if an insertion, update or removal should
		## really be executed. Parameters are the same as for the event. If true is
		## returned, the update is performed. If false is returned, it is skipped.
		pred: function(typ: Input::Event, left: any, right: any): bool &optional;

		## A key/value table that will be passed on the reader.
		## Interpretation of the values is left to the writer, but
		## usually they will be used for configuration purposes.
                config: table[string] of string &default=table();
	};

	## EventFilter description type used for the `event` method.
	type EventDescription: record {
		# Common definitions for tables and events

		## String that allows the reader to find the source.
		## For `READER_ASCII`, this is the filename.
		source: string;

		## Reader to use for this stream.
		reader: Reader &default=default_reader;

		## Read mode to use for this stream.
		mode: Mode &default=default_mode;

		## Descriptive name. Used to remove a stream at a later time.
		name: string;

		# Special definitions for events

		## Record describing the fields to be retrieved from the source input.
		fields: any;

		## If this is false, the event receives each value in fields as a separate argument.
		## If this is set to true (default), the event receives all fields in a single record value.
		want_record: bool &default=T;

		## The event that is raised each time a new line is received from the reader.
		## The event will receive an Input::Event enum as the first element, and the fields as the following arguments.
		ev: any;

		## A key/value table that will be passed on the reader.
		## Interpretation of the values is left to the writer, but
		## usually they will be used for configuration purposes.
		config: table[string] of string &default=table();
	};

	## A file analysis input stream type used to forward input data to the
	## file analysis framework.
	type AnalysisDescription: record {
		## String that allows the reader to find the source.
		## For `READER_ASCII`, this is the filename.
		source: string;

		## Reader to use for this stream.  Compatible readers must be
		## able to accept a filter of a single string type (i.e.
		## they read a byte stream).
		reader: Reader &default=Input::READER_BINARY;

		## Read mode to use for this stream.
		mode: Mode &default=default_mode;

		## Descriptive name that uniquely identifies the input source.
		## Can be used to remove a stream at a later time.
		## This will also be used for the unique *source* field of
		## :bro:see:`fa_file`.  Most of the time, the best choice for this
		## field will be the same value as the *source* field.
		name: string;

		## A key/value table that will be passed on the reader.
		## Interpretation of the values is left to the writer, but
		## usually they will be used for configuration purposes.
		config: table[string] of string &default=table();
	};

	## Create a new table input from a given source.
	##
	## description: `TableDescription` record describing the source.
	##
	## Returns: true on success.
	global add_table: function(description: Input::TableDescription) : bool;

	## Create a new event input from a given source.
	##
	## description: `EventDescription` record describing the source.
	##
	## Returns: true on success.
	global add_event: function(description: Input::EventDescription) : bool;

	## Create a new file analysis input from a given source.  Data read from
	## the source is automatically forwarded to the file analysis framework.
	##
	## description: A record describing the source.
	##
	## Returns: true on success.
	global add_analysis: function(description: Input::AnalysisDescription) : bool;

	## Remove an input stream.
	##
	## id: string value identifying the stream to be removed.
	##
	## Returns: true on success and false if the named stream was not found.
	global remove: function(id: string) : bool;

	## Forces the current input to be checked for changes.
	##
	## id: string value identifying the stream.
	##
	## Returns: true on success and false if the named stream was not found.
	global force_update: function(id: string) : bool;

	## Event that is called when the end of a data source has been reached,
	## including after an update.
	global end_of_data: event(name: string, source:string);
}

@load base/bif/input.bif


module Input;

function add_table(description: Input::TableDescription) : bool
	{
	return __create_table_stream(description);
	}

function add_event(description: Input::EventDescription) : bool
	{
	return __create_event_stream(description);
	}

function add_analysis(description: Input::AnalysisDescription) : bool
	{
	return __create_analysis_stream(description);
	}

function remove(id: string) : bool
	{
	return __remove_stream(id);
	}

function force_update(id: string) : bool
	{
	return __force_update(id);
	}

