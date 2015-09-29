##! The input framework provides a way to read previously stored data either
##! as an event stream or into a Bro table.

module Input;

export {
	type Event: enum {
		## New data has been imported.
		EVENT_NEW = 0,
		## Existing data has been changed.
		EVENT_CHANGED = 1,
		## Previously existing data has been removed.
		EVENT_REMOVED = 2,
	};

	## Type that defines the input stream read mode.
	type Mode: enum {
		## Do not automatically reread the file after it has been read.
		MANUAL = 0,
		## Reread the entire file each time a change is found.
		REREAD = 1,
		## Read data from end of file each time new data is appended.
		STREAM = 2
	};

	## The default input reader used. Defaults to `READER_ASCII`.
	const default_reader = READER_ASCII &redef;

	## The default reader mode used. Defaults to `MANUAL`.
	const default_mode = MANUAL &redef;

	## Separator between fields.
	## Please note that the separator has to be exactly one character long.
	## Individual readers can use a different value.
	const separator = "\t" &redef;

	## Separator between set elements.
	## Please note that the separator has to be exactly one character long.
	## Individual readers can use a different value.
	const set_separator = "," &redef;

	## String to use for empty fields.
	## Individual readers can use a different value.
	const empty_field = "(empty)" &redef;

	## String to use for an unset &optional field.
	## Individual readers can use a different value.
	const unset_field = "-" &redef;

	## Flag that controls if the input framework accepts records
	## that contain types that are not supported (at the moment
	## file and function). If true, the input framework will
	## warn in these cases, but continue. If false, it will
	## abort. Defaults to false (abort).
	const accept_unsupported_types = F &redef;

	## A table input stream type used to send data to a Bro table.
	type TableDescription: record {
		# Common definitions for tables and events

		## String that allows the reader to find the source of the data.
		## For `READER_ASCII`, this is the filename.
		source: string;

		## Reader to use for this stream.
		reader: Reader &default=default_reader;

		## Read mode to use for this stream.
		mode: Mode &default=default_mode;

		## Name of the input stream.  This is used by some functions to
		## manipulate the stream.
		name: string;

		# Special definitions for tables

		## Table which will receive the data read by the input framework.
		destination: any;

		## Record that defines the values used as the index of the table.
		idx: any;

		## Record that defines the values used as the elements of the table.
		## If this is undefined, then *destination* must be a set.
		val: any &optional;

		## Defines if the value of the table is a record (default), or a single
		## value. When this is set to false, then *val* can only contain one
		## element.
		want_record: bool &default=T;

		## The event that is raised each time a value is added to, changed in,
		## or removed from the table. The event will receive an
		## Input::TableDescription as the first argument, an Input::Event
		## enum as the second argument, the *idx* record as the third argument
		## and the value (record) as the fourth argument.
		ev: any &optional;

		## Predicate function that can decide if an insertion, update or removal
		## should really be executed. Parameters have same meaning as for the
		## event.
		## If true is returned, the update is performed. If false is returned,
		## it is skipped.
		pred: function(typ: Input::Event, left: any, right: any): bool &optional;

		## A key/value table that will be passed to the reader.
		## Interpretation of the values is left to the reader, but
		## usually they will be used for configuration purposes.
		config: table[string] of string &default=table();
	};

	## An event input stream type used to send input data to a Bro event.
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

		## Record type describing the fields to be retrieved from the input
		## source.
		fields: any;

		## If this is false, the event receives each value in *fields* as a
		## separate argument.
		## If this is set to true (default), the event receives all fields in
		## a single record value.
		want_record: bool &default=T;

		## The event that is raised each time a new line is received from the
		## reader. The event will receive an Input::EventDescription record
		## as the first argument, an Input::Event enum as the second
		## argument, and the fields (as specified in *fields*) as the following
		## arguments (this will either be a single record value containing
		## all fields, or each field value as a separate argument).
		ev: any;

		## A key/value table that will be passed to the reader.
		## Interpretation of the values is left to the reader, but
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

		## A key/value table that will be passed to the reader.
		## Interpretation of the values is left to the reader, but
		## usually they will be used for configuration purposes.
		config: table[string] of string &default=table();
	};

	## Create a new table input stream from a given source.
	##
	## description: `TableDescription` record describing the source.
	##
	## Returns: true on success.
	global add_table: function(description: Input::TableDescription) : bool;

	## Create a new event input stream from a given source.
	##
	## description: `EventDescription` record describing the source.
	##
	## Returns: true on success.
	global add_event: function(description: Input::EventDescription) : bool;

	## Create a new file analysis input stream from a given source.  Data read
	## from the source is automatically forwarded to the file analysis
	## framework.
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
	##
	## name: Name of the input stream.
	##
	## source: String that identifies the data source (such as the filename).
	global end_of_data: event(name: string, source: string);
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

