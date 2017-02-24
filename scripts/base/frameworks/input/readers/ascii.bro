##! Interface for the ascii input reader.
##!
##! The defaults are set to match Bro's ASCII output.

module InputAscii;

export {
	## Separator between fields.
	## Please note that the separator has to be exactly one character long.
	const separator = Input::separator &redef;

	## Separator between set elements.
	## Please note that the separator has to be exactly one character long.
	const set_separator = Input::set_separator &redef;

	## String to use for empty fields.
	const empty_field = Input::empty_field &redef;

	## String to use for an unset &optional field.
	const unset_field = Input::unset_field &redef;

	## Choose if the ascii input reader should globally
	## fail on invalid lines and continue parsing afterward.
	## Individual readers can use a different value.
	const fail_on_invalid_lines = F &redef;

	## Set to true if you would like the old behavior of the 
	## ascii reader where the reader thread would die if any file 
	## errors occur (like permissions problems or file missing). 
	## The default behavior is to continue attempting to open and read
	## the file even in light of problems.
	## Individual readers can use a different value.
	const fail_on_file_problem = F &redef;
}
