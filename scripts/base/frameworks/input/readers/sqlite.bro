##! Interface for the SQLite input reader. Redefinable options are available
##! to tweak the input format of the SQLite reader.
##!
##! See :doc:`/frameworks/logging-input-sqlite` for an introduction on how to
##! use the SQLite reader.
##!
##! When using the SQLite reader, you have to specify the SQL query that returns
##! the desired data by setting ``query`` in the ``config`` table. See the
##! introduction mentioned above for an example.

module InputSQLite;

export {
	## Separator between set elements.
	## Please note that the separator has to be exactly one character long.
	const set_separator = Input::set_separator &redef;

	## String to use for an unset &optional field.
	const unset_field = Input::unset_field &redef;

	## String to use for empty fields.
	const empty_field = Input::empty_field &redef;
}
