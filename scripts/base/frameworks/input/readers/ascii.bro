##! Interface for the ascii input reader.

module InputAscii;

export {
	## Separator between fields.
	## Please note that the separator has to be exactly one character long
	const separator = "\t" &redef;

	## Separator between set elements.
	## Please note that the separator has to be exactly one character long
	const set_separator = "," &redef;

	## String to use for empty fields.
	const empty_field = "(empty)" &redef;

	## String to use for an unset &optional field.
	const unset_field = "-" &redef;
}
