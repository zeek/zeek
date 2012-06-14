##! Interface for the SQLite log writer.  Redefinable options are available
##! to tweak the output format of the SQLite reader.

module LogSQLite;

export {
	## Separator between set elements.
	const set_separator = "," &redef;
}

