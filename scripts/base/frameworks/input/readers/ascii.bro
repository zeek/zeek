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
}
