##! Interface for the SQLite log writer. Redefinable options are available
##! to tweak the output format of the SQLite reader.
##!
##! See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
##! use the SQLite log writer.
##!
##! The SQL writer currently supports one writer-specific filter option via
##! ``config``: setting ``tablename`` sets the name of the table that is used
##! or created in the SQLite database. An example for this is given in the
##! introduction mentioned above.

module LogSQLite;

export {
	## Separator between set elements.
	const set_separator = Log::set_separator &redef;

	## String to use for an unset &optional field.
	const unset_field = Log::unset_field &redef;

	## String to use for empty fields. This should be different from
        ## *unset_field* to make the output unambiguous.
	const empty_field = Log::empty_field &redef;
}

