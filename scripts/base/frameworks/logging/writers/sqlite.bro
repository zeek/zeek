##! Interface for the SQLite log writer.  Redefinable options are available
##! to tweak the output format of the SQLite reader.

module LogSQLite;

export {
	## Separator between set elements.
	const set_separator = Log::set_separator &redef;

	## String to use for an unset &optional field.
	const unset_field = Log::unset_field &redef;
}

